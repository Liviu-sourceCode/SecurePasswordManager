// Content script for Password Manager extension
// Production-safe logging wrapper: redacts secrets and gates debug logs
(function initSafeLogging(){
  const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, none: 100 };
  let level = 'info';
  const redactKeys = new Set(['password','encrypted_password','nonce','encryption_key','session_token']);
  const seenMark = typeof WeakSet !== 'undefined' ? WeakSet : Set;
  function sanitize(obj, seen = new seenMark()){
    if (obj == null || typeof obj !== 'object') return obj;
    try { if (seen.has(obj)) return obj; seen.add(obj); } catch(_) {}
    if (Array.isArray(obj)) return obj.map(v => sanitize(v, seen));
    const clone = {};
    for (const [k, v] of Object.entries(obj)){
      if (redactKeys.has(k)) clone[k] = '[redacted]';
      else clone[k] = sanitize(v, seen);
    }
    return clone;
  }
  function shouldLog(target){
    return LEVELS[target] >= LEVELS[level] && level !== 'none';
  }
  const orig = {
    log: console.log.bind(console),
    info: console.info.bind(console),
    debug: console.debug.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console)
  };
  function wrap(fn, target){
    return (...args) => {
      if (!shouldLog(target)) return;
      const sanitized = args.map(a => (typeof a === 'object' ? sanitize(a) : a));
      fn(...sanitized);
    };
  }
  console.debug = wrap(orig.debug, 'debug');
  console.info = wrap(orig.info, 'info');
  console.log = wrap(orig.log, 'info');
  console.warn = wrap(orig.warn, 'warn');
  console.error = wrap(orig.error, 'error');

  try {
    chrome.storage.managed.get({ logLevel: null }, (res) => {
      if (res && res.logLevel && LEVELS[res.logLevel]) {
        level = res.logLevel;
      } else {
        chrome.storage.local.get({ logLevel: null }, (res2) => {
          if (res2 && res2.logLevel && LEVELS[res2.logLevel]) {
            level = res2.logLevel;
          }
        });
      }
    });
  } catch (_) {}
})();
class FormDetector {
  constructor() {
    this.forms = new Set();
    this.credentials = null;
    this.domain = this.extractDomain(window.location.href);
    this.autoFillEnabled = true; // Enable automatic filling by default
    this.credentialPickerActive = false; // prevent duplicate prompts
    this.autoPromptShown = false; // avoid repeated prompts per page load
    this.setupEventListeners();
    this.detectForms();
  }

  // AES-GCM decrypt of host-provided password
  async decryptHostPassword(encryptedB64, nonceB64, keyB64) {
    try {
      const b64ToBytes = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      const ct = b64ToBytes(encryptedB64);
      const iv = b64ToBytes(nonceB64);
      const keyBytes = b64ToBytes(keyB64);
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );
      const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ct);
      return new TextDecoder().decode(plainBuf);
    } catch (err) {
      console.error('Password decrypt failed:', err);
      return null;
    }
  }

  extractDomain(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch (error) {
      return '';
    }
  }

  setupEventListeners() {
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      switch (message.type) {
        case 'pageLoaded':
          this.detectForms();
          break;
        case 'fillCredentials':
          this.fillForm(message.credentials);
          break;
        case 'credentialsFound':
          // Handle proactive credentials from background script
          this.handleProactiveCredentials(message.credentials);
          break;
        case 'showPasswordPrompt':
          this.showPasswordPrompt(message.message);
          sendResponse({ success: true });
          break;
        case 'showTotpPrompt':
          this.showTotpPrompt(message.message);
          sendResponse({ success: true });
          break;
      }
    });

    // Listen for form submissions
    document.addEventListener('submit', (event) => {
      this.handleFormSubmit(event);
    });

    // Listen for input changes to detect new forms
    document.addEventListener('input', (event) => {
      if (this.isPasswordField(event.target) || this.isUsernameField(event.target)) {
        this.detectForms();
      }
    });

    // Listen for DOM changes
    const observer = new MutationObserver((mutations) => {
      let shouldDetect = false;
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList' || mutation.type === 'attributes') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (node.tagName === 'FORM' || node.querySelector?.('form') || node.querySelector?.('input[type="password"]')) {
                shouldDetect = true;
              }
            }
          });
        }
      });
      if (shouldDetect) {
        setTimeout(() => this.detectForms(), 100);
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true
    });

    // SPA navigation hooks
    try {
      const origPush = history.pushState.bind(history);
      const origReplace = history.replaceState.bind(history);
      history.pushState = (...args) => { const ret = origPush(...args); setTimeout(() => this.detectForms(), 50); return ret; };
      history.replaceState = (...args) => { const ret = origReplace(...args); setTimeout(() => this.detectForms(), 50); return ret; };
      window.addEventListener('popstate', () => setTimeout(() => this.detectForms(), 50));
      window.addEventListener('hashchange', () => setTimeout(() => this.detectForms(), 50));
      document.addEventListener('visibilitychange', () => { if (!document.hidden) setTimeout(() => this.detectForms(), 50); });
    } catch(_) {}
  }

  detectForms() {
    const forms = document.querySelectorAll('form');
    let foundNewForms = false;

    forms.forEach(form => {
      if (!this.forms.has(form)) {
        const loginForm = this.analyzeForm(form);
        if (loginForm) {
          this.forms.add(form);
          this.enhanceForm(form, loginForm);
          foundNewForms = true;
        }
      }
    });

    // Also check for forms without <form> tags
    this.detectFormlessLogins();

    if (foundNewForms) {
      this.searchAndAutoFillCredentials();
    }
  }

  analyzeForm(form) {
    const inputs = [
      ...form.querySelectorAll('input'),
      ...this.queryAllDeep(form, 'input')
    ];
    let usernameField = null;
    let passwordField = null;

    inputs.forEach(input => {
      if (this.isPasswordField(input)) {
        passwordField = input;
      } else if (this.isUsernameField(input)) {
        usernameField = input;
      }
    });

    // Consider contenteditable username candidates if not found yet
    if (!usernameField) {
      const editables = this.queryAllDeep(form, '[contenteditable="true"]');
      for (const ed of editables) {
        if (this.isContentEditableField(ed) && this.isUsernameField(ed)) {
          usernameField = ed;
          break;
        }
      }
    }

    if (passwordField) {
      return {
        form: form,
        usernameField: usernameField,
        passwordField: passwordField,
        submitButton: this.findSubmitButton(form)
      };
    }

    return null;
  }

  // Helper: query selectors across shadow roots
  queryAllDeep(root, selector) {
    const results = [];
    const traverse = (node) => {
      if (!node) return;
      if (node.nodeType === Node.ELEMENT_NODE || node.nodeType === Node.DOCUMENT_FRAGMENT_NODE) {
        // Regular query
        try { results.push(...node.querySelectorAll(selector)); } catch(_) {}
        // Shadow root
        const shadow = node.shadowRoot || (node instanceof ShadowRoot ? node : null);
        if (shadow) traverse(shadow);
      }
      // Walk children
      if (node.children) {
        for (const child of node.children) traverse(child);
      }
    };
    traverse(root);
    return results;
  }

  // Helper: get label text associated with input/textarea/contenteditable
  getLabelText(el) {
    try {
      const id = el.id;
      let text = '';
      if (id) {
        const label = document.querySelector(`label[for="${CSS.escape(id)}"]`);
        if (label && label.textContent) text = label.textContent.trim();
      }
      if (!text && el.closest) {
        const parentLabel = el.closest('label');
        if (parentLabel && parentLabel.textContent) text = parentLabel.textContent.trim();
      }
      if (!text) {
        const aria = el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || '';
        text = aria.trim();
      }
      return (text || '').toLowerCase();
    } catch(_) { return ''; }
  }

  // Helper: get unified field value
  getFieldValue(field) {
    if (!field) return '';
    if (field.tagName === 'INPUT' || field.tagName === 'TEXTAREA') return field.value || '';
    if (field.isContentEditable) return field.textContent || '';
    return '';
  }

  // Helper: simulate keystrokes as a last-resort fallback
  async simulateKeystrokes(field, value) {
    try {
      const isInput = field.tagName === 'INPUT' || field.tagName === 'TEXTAREA';
      const isEditable = !!field.isContentEditable;

      const setVal = (v) => {
        try {
          let proto = null;
          if (field.tagName === 'INPUT') proto = HTMLInputElement.prototype;
          else if (field.tagName === 'TEXTAREA') proto = HTMLTextAreaElement.prototype;
          const descriptor = proto ? Object.getOwnPropertyDescriptor(proto, 'value') : null;
          if (descriptor && typeof descriptor.set === 'function') descriptor.set.call(field, v);
          else if (isEditable) field.textContent = v;
          else field.value = v;
        } catch(_) { if (isEditable) field.textContent = v; else field.value = v; }
      };

      // Clear existing content
      setVal('');
      field.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true, inputType: 'deleteContentBackward' }));

      for (const ch of String(value)) {
        const key = ch.length === 1 ? ch : 'Unidentified';
        field.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, composed: true }));
        field.dispatchEvent(new KeyboardEvent('keypress', { key, bubbles: true, composed: true }));
        // Append char
        const current = this.getFieldValue(field);
        setVal(current + ch);
        field.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true, inputType: 'insertText', data: ch }));
        field.dispatchEvent(new KeyboardEvent('keyup', { key, bubbles: true, composed: true }));
        await new Promise(r => setTimeout(r, 2));
      }

      field.dispatchEvent(new Event('change', { bubbles: true }));
      field.dispatchEvent(new Event('blur', { bubbles: true }));
    } catch(_) {}
  }

  // Helper: treat contenteditable as username-capable fields
  isContentEditableField(el) {
    return !!el && el.isContentEditable && (el.getAttribute('role') || '').toLowerCase().includes('textbox');
  }

  detectFormlessLogins() {
    // Detect login forms that don't use <form> tags and traverse shadow roots
    const candidateInputs = [
      ...document.querySelectorAll('input'),
      ...this.queryAllDeep(document, 'input')
    ];
    const passwordInputs = candidateInputs.filter(input => this.isPasswordField(input));
    let created = false;

    passwordInputs.forEach(passwordInput => {
      let container = passwordInput.closest('div, section, main, body') || passwordInput.getRootNode();
      if (container && !this.forms.has(container)) {
        // Try nearby username/email first
        let usernameInput = this.findNearbyUsernameField(passwordInput) ||
          (this.queryAllDeep(container, 'input[type="email"], input[type="text"]').find(i => this.isUsernameField(i)) || null);

        // n8n-specific local fallback: explicit field name for email within the same container
        if (!usernameInput) {
          const n8nEmailLocal = this.queryAllDeep(container, 'input[name="emailOrLdapLoginId"]').find(i => i) || null;
          if (n8nEmailLocal) usernameInput = n8nEmailLocal;
        }

        // n8n-specific global fallback: search document-wide if components are separated
        if (!usernameInput) {
          const n8nEmailGlobal = this.queryAllDeep(document, 'input[name="emailOrLdapLoginId"]').find(i => i) || null;
          if (n8nEmailGlobal) usernameInput = n8nEmailGlobal;
        }

        if (usernameInput) {
          // Ensure the chosen container contains both fields; fallback to document.body otherwise
          if (!container.contains(usernameInput)) {
            container = document.body;
          }

          const submit = this.findNearbySubmitButton(passwordInput) ||
            this.findSubmitButton(container) ||
            this.findSubmitButton(document.body);

          const loginForm = {
            form: container,
            usernameField: usernameInput,
            passwordField: passwordInput,
            submitButton: submit
          };
          this.forms.add(container);
          this.enhanceForm(container, loginForm);
          created = true;
        }
      }
    });

    if (created) {
      this.searchAndAutoFillCredentials();
    }
  }

  isPasswordField(input) {
    if (!input || input.tagName !== 'INPUT') return false;
    const type = (input.type || '').toLowerCase();
    const autocomplete = (input.autocomplete || '').toLowerCase();
    if (type === 'password' || autocomplete === 'current-password' || autocomplete === 'new-password') return true;
    // Heuristic: some sites toggle to text to show password or use custom inputs
    if (['text','email','tel','search','number'].includes(type)) {
      const name = (input.name || '').toLowerCase();
      const id = (input.id || '').toLowerCase();
      const placeholder = (input.placeholder || '').toLowerCase();
      const aria = ((input.getAttribute('aria-label')||'') + ' ' + (input.getAttribute('aria-labelledby')||'')).toLowerCase();
      const label = this.getLabelText(input);
      const passKeywords = ['password','passcode','pin','mot de passe','contraseña','senha','пароль','密码','パスワード','비밀번호'];
      return passKeywords.some(k => name.includes(k) || id.includes(k) || placeholder.includes(k) || aria.includes(k) || label.includes(k));
    }
    return false;
  }

  isUsernameField(el) {
    if (!el) return false;
    // Input elements
    if (el.tagName === 'INPUT') {
      const type = (el.type || '').toLowerCase();
      if (!['text','email','tel','search'].includes(type)) return false;
      const name = (el.name || '').toLowerCase();
      const id = (el.id || '').toLowerCase();
      const placeholder = (el.placeholder || '').toLowerCase();
      const autocomplete = (el.autocomplete || '').toLowerCase();
      const aria = ((el.getAttribute('aria-label')||'') + ' ' + (el.getAttribute('aria-labelledby')||'')).toLowerCase();
      const label = this.getLabelText(el);
      const keywords = ['username','user','email','login','account','id','identifier'];
      const matched = keywords.some(k => name.includes(k) || id.includes(k) || placeholder.includes(k) || autocomplete.includes(k) || aria.includes(k) || label.includes(k));
      return matched || autocomplete === 'username' || autocomplete === 'email';
    }
    // Contenteditable textboxes
    if (this.isContentEditableField(el)) {
      const aria = ((el.getAttribute('aria-label')||'') + ' ' + (el.getAttribute('aria-labelledby')||'')).toLowerCase();
      const label = this.getLabelText(el);
      const placeholder = (el.getAttribute('placeholder') || el.getAttribute('data-placeholder') || '').toLowerCase();
      const keywords = ['username','user','email','login','account','id','identifier'];
      return keywords.some(k => label.includes(k) || aria.includes(k) || placeholder.includes(k));
    }
    return false;
  }

  findNearbyUsernameField(passwordInput) {
    const container = passwordInput.closest('div, section, form, main, body') || passwordInput.getRootNode();
    if (!container) return null;

    const inputs = [
      ...container.querySelectorAll('input[type="text"], input[type="email"], textarea'),
      ...this.queryAllDeep(container, 'input[type="text"], input[type="email"], textarea'),
      ...this.queryAllDeep(container, '[contenteditable="true"]')
    ];

    for (let input of inputs) {
      if (this.isUsernameField(input)) {
        return input;
      }
    }

    return null;
  }

  findSubmitButton(form) {
    // Deep scan for buttons, inputs, anchors or custom elements acting as submit
    const candidates = [
      ...this.queryAllDeep(form, 'button, input[type="submit"], input[type="button"], [role="button"], a[role="button"], a.button, .btn, [class*="button"], [class*="btn"]')
    ];

    const loginRegex = /(login|log in|sign in|signin|submit|continue|next|start|authorize|ok|go|enter|proceed|connexion|se connecter|iniciar sesión|accedi|entrar|anmelden|войти|登录|登入|ログイン|로그인)/i;

    for (const el of candidates) {
      const text = (el.textContent || el.value || el.getAttribute('aria-label') || '').trim().toLowerCase();
      if (loginRegex.test(text)) return el;
      // Accept icon-only primary buttons
      const tag = el.tagName.toLowerCase();
      if (tag === 'button' || (tag === 'input' && (el.type === 'submit' || el.type === 'button')) || el.getAttribute('role') === 'button') {
        if (!text) return el;
      }
    }

    // Fallback to standard submit
    return form.querySelector('button[type="submit"], input[type="submit"]') || null;
  }

  findNearbySubmitButton(passwordInput) {
    const container = passwordInput.closest('div, section, form, main, body') || passwordInput.getRootNode();
    if (!container) return null;
    return this.findSubmitButton(container);
  }

  enhanceForm(container, loginForm) {
    // Mark form as enhanced to avoid duplicate processing
    if (loginForm.passwordField.dataset.pmEnhanced) return;
    loginForm.passwordField.dataset.pmEnhanced = 'true';
    
    // Add form submission listener
    if (loginForm.submitButton) {
      loginForm.submitButton.addEventListener('click', () => {
        setTimeout(() => this.handleFormSubmit({ target: loginForm.form }), 100);
      });
    }

    // Add focus listeners to trigger auto-fill when user interacts with form
    if (loginForm.usernameField) {
      loginForm.usernameField.addEventListener('focus', () => {
        this.tryAutoFillForm(loginForm);
      });
    }
    
    if (loginForm.passwordField) {
      loginForm.passwordField.addEventListener('focus', () => {
        this.tryAutoFillForm(loginForm);
      });
    }
  }

  async searchAndAutoFillCredentials() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'searchCredentials',
        domain: this.domain,
        url: window.location.href
      });

      if (response && !response.error) {
        this.credentials = response.credentials || [];
        console.log(`Found ${this.credentials.length} credentials for ${this.domain}`);
        
        if (!this.autoFillEnabled || !this.credentials || this.credentials.length === 0) return;
        
        // If more than one credential exists, show selector automatically
        if (this.credentials.length > 1) {
          this.presentCredentialSelection();
        } else if (this.credentials.length === 1) {
          // Automatically fill forms if a single credential is found
          this.autoFillAllForms();
        }
      }
    } catch (error) {
      console.error('Error searching credentials:', error);
    }
  }

  handleProactiveCredentials(credentials) {
    // Store the credentials received from background script
    this.credentials = credentials || [];
    console.log(`Received ${this.credentials.length} credentials from background script for ${this.domain}`);
    
    if (!this.autoFillEnabled || !this.credentials || this.credentials.length === 0) return;
    
    // Only prompt or auto-fill if we have detected at least one login form on the page
    const hasLoginForms = this.forms && this.forms.size > 0;
    if (!hasLoginForms) {
      // Defer any prompting until a login form is detected
      return;
    }
    
    // Automatically prompt if multiple credentials are found; otherwise auto-fill
    if (this.credentials.length > 1) {
      this.presentCredentialSelection();
    } else {
      this.autoFillAllForms();
    }
  }

  autoFillAllForms() {
    // Auto-fill all detected forms with the first available credential
    if (!this.credentials || this.credentials.length === 0) return;

    const fillWithCredential = async () => {
      let credential = { ...this.credentials[0] }; // Use first credential

      // Fetch password from background if not present
      if (!credential.password && credential.id) {
        try {
          const resp = await chrome.runtime.sendMessage({
            type: 'getCredentialPassword',
            id: credential.id
          });
          if (resp && resp.type === 'passwordResult' && resp.success) {
            if (resp.password) {
              credential.password = resp.password;
            } else if (resp.encrypted_password && resp.nonce && resp.encryption_key) {
              const pw = await this.decryptHostPassword(resp.encrypted_password, resp.nonce, resp.encryption_key);
              if (pw) credential.password = pw;
            }
          }
        } catch (e) {
          console.warn('Failed to fetch password for auto-fill:', e);
        }
      }

      for (let form of this.forms) {
        const loginForm = this.analyzeForm(form);
        if (loginForm && this.shouldAutoFill(loginForm)) {
          this.fillForm(credential, loginForm);
        }
      }
    };

    // Run async without blocking
    fillWithCredential();
  }

  shouldAutoFill(loginForm) {
    // Auto-fill when either field is empty (supports inputs and contenteditable)
    const usernameEmpty = !loginForm.usernameField || !this.getFieldValue(loginForm.usernameField).trim();
    const passwordEmpty = !loginForm.passwordField || !this.getFieldValue(loginForm.passwordField).trim();
    return usernameEmpty || passwordEmpty;
  }

  async tryAutoFillForm(loginForm) {
    // Try to auto-fill when user focuses on form fields
    if (!this.credentials || this.credentials.length === 0) {
      await this.searchAndAutoFillCredentials();
      return;
    }

    if (!this.autoFillEnabled) return;

    if (this.credentials.length > 1) {
      // Show selection if multiple credentials exist
      this.presentCredentialSelection();
      return;
    }

    if (this.credentials.length > 0 && this.shouldAutoFill(loginForm)) {
      let credential = { ...this.credentials[0] };
      if (!credential.password && credential.id) {
        try {
          const resp = await chrome.runtime.sendMessage({
            type: 'getCredentialPassword',
            id: credential.id
          });
          if (resp && resp.type === 'passwordResult' && resp.success) {
            if (resp.password) {
              credential.password = resp.password;
            } else if (resp.encrypted_password && resp.nonce && resp.encryption_key) {
              const pw = await this.decryptHostPassword(resp.encrypted_password, resp.nonce, resp.encryption_key);
              if (pw) credential.password = pw;
            }
          }
        } catch (e) {
          console.warn('Failed to fetch password for focused auto-fill:', e);
        }
      }
      this.fillForm(credential, loginForm);
    }
  }

  fillForm(credentials, loginForm = null) {
    if (!loginForm) {
      // Find the first available form
      for (let form of this.forms) {
        const formData = this.analyzeForm(form);
        if (formData) {
          loginForm = formData;
          break;
        }
      }
    }

    if (!loginForm) return;

    // Fill username
    if (loginForm.usernameField && credentials.username) {
      this.fillField(loginForm.usernameField, credentials.username);
    }

    // Fill password if available
    if (loginForm.passwordField && credentials.password) {
      this.fillField(loginForm.passwordField, credentials.password);
    }

    console.log('Form auto-filled for', this.domain);
  }

  fillField(field, value) {
     try {
       // Focus first so frameworks attach listeners
       if (typeof field.focus === 'function') {
         field.focus();
       }

       // Choose appropriate native setter
       let proto = null;
       if (field.tagName === 'INPUT') proto = HTMLInputElement.prototype;
       else if (field.tagName === 'TEXTAREA') proto = HTMLTextAreaElement.prototype;
       const descriptor = proto ? Object.getOwnPropertyDescriptor(proto, 'value') : null;

       if (descriptor && typeof descriptor.set === 'function') {
         descriptor.set.call(field, value);
       } else if (field.isContentEditable) {
         field.textContent = value;
       } else {
         field.value = value;
       }

       // Dispatch input event (use InputEvent when available)
       const inputEvt = (typeof InputEvent === 'function')
         ? new InputEvent('input', { bubbles: true, cancelable: true, composed: true, data: value })
         : new Event('input', { bubbles: true });
       field.dispatchEvent(inputEvt);

       // Also dispatch change and blur to satisfy various frameworks
       field.dispatchEvent(new Event('change', { bubbles: true }));
       field.dispatchEvent(new Event('blur', { bubbles: true }));

       // Verify; fallback to keystrokes if framework blocked programmatic set
       const filled = this.getFieldValue(field) || '';
       if (String(filled) !== String(value)) {
         this.simulateKeystrokes(field, value);
       }
     } catch (e) {
       // Fallback in case of any unexpected error
       if (field.isContentEditable) field.textContent = value; else field.value = value;
       field.dispatchEvent(new Event('input', { bubbles: true }));
       field.dispatchEvent(new Event('change', { bubbles: true }));
       field.dispatchEvent(new Event('blur', { bubbles: true }));
     }
   }

  showPasswordPrompt(message) {
    this.createSecurePasswordDialog(message);
  }

  showTotpPrompt(message) {
    this.createTotpDialog(message);
  }

  createSecurePasswordDialog(message) {
    // Remove any existing dialog
    const existingDialog = document.getElementById('password-manager-dialog');
    if (existingDialog) {
      existingDialog.remove();
    }

    // Create overlay
    const overlay = document.createElement('div');
    overlay.id = 'password-manager-dialog';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(16, 18, 27, 0.66);
      backdrop-filter: blur(2px);
      z-index: 999999;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    // Create dialog
    const dialog = document.createElement('div');
    dialog.style.cssText = `
      background: #0b0f16;
      border: 1px solid #1f2937;
      border-radius: 10px;
      padding: 18px 18px 14px 18px;
      box-shadow: 0 16px 40px rgba(0,0,0,0.35);
      max-width: 440px;
      width: calc(100% - 32px);
      position: relative;
      transform: translateY(8px);
      opacity: 0;
      transition: opacity .18s ease-out, transform .18s ease-out;
      color: #e5e7eb;
    `;

    // Create content
    const domainLabel = this.domain ? `<span style="color:#94a3b8;font-size:12px;">${this.domain}</span>` : '';
    dialog.innerHTML = `
      <div style="margin-bottom:12px;">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
          <h3 style="margin:0;color:#e5e7eb;font-size:16px;font-weight:600;">Password Manager</h3>
          ${domainLabel}
        </div>
        <p style="margin:6px 0 0;color:#94a3b8;font-size:13px;">${message || 'Enter your master password to unlock credentials.'}</p>
      </div>
      <div style="margin:12px 0 16px;position:relative;">
        <label for="password-input" style="display:block;color:#cbd5e1;font-size:12px;font-weight:600;margin-bottom:6px;">Master Password</label>
        <input type="password" id="password-input" aria-label="Master password" placeholder="Enter your master password" 
               style="width:100%;padding:10px 40px 10px 10px;border:1px solid #334155;border-radius:6px;font-size:14px;box-sizing:border-box;outline:none;background:#0f141d;color:#e5e7eb;">
        <button id="toggle-visibility" type="button" aria-label="Show password" title="Show password"
                style="position:absolute;right:8px;top:32px;height:24px;width:24px;border:1px solid transparent;background:transparent;color:#a78bfa;cursor:pointer;font-size:14px;">👁️</button>
      </div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-top:4px;">
        <div style="color:#94a3b8;font-size:12px;">Enter to submit · Esc to cancel</div>
        <div style="display:flex;gap:8px;">
          <button id="cancel-btn" style="padding:8px 14px;border:1px solid #334155;background:#0b0f16;border-radius:6px;cursor:pointer;font-size:14px;color:#e5e7eb;">Cancel (Esc)</button>
          <button id="ok-btn" style="padding:8px 14px;border:1px solid #4f46e5;background:#0b0f16;color:#c7d2fe;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600;">OK</button>
        </div>
      </div>
    `;

    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Get elements
    const passwordInput = dialog.querySelector('#password-input');
    const okBtn = dialog.querySelector('#ok-btn');
    const cancelBtn = dialog.querySelector('#cancel-btn');

    // Fade-in animation
    requestAnimationFrame(() => {
      dialog.style.transform = 'translateY(0)';
      dialog.style.opacity = '1';
    });

    // Focus password input
    passwordInput.focus();

    // Add input styling on focus
    passwordInput.addEventListener('focus', () => {
      passwordInput.style.borderColor = '#4f46e5';
      passwordInput.style.boxShadow = '0 0 0 2px rgba(79,70,229,0.20)';
    });
    passwordInput.addEventListener('blur', () => {
      passwordInput.style.borderColor = '#334155';
      passwordInput.style.boxShadow = 'none';
    });

    // Handle OK button
    const handleOk = () => {
      const password = passwordInput.value;
      if (password) {
        overlay.remove();
        // Send plaintext over extension messaging (isolated from page scripts)
        chrome.runtime.sendMessage({
          type: 'passwordPromptResponse',
          encrypted: false,
          password
        });
      } else {
        passwordInput.style.borderColor = '#e74c3c';
        passwordInput.focus();
      }
    };

    // Disable OK until text present
    const okBtnInitialDisable = () => { okBtn.disabled = !passwordInput.value; okBtn.style.opacity = okBtn.disabled ? '0.6' : '1'; okBtn.style.cursor = okBtn.disabled ? 'not-allowed' : 'pointer'; };
    okBtnInitialDisable();
    passwordInput.addEventListener('input', okBtnInitialDisable);

    // Toggle visibility
    const toggleBtn = dialog.querySelector('#toggle-visibility');
    toggleBtn.addEventListener('click', () => {
      const isHidden = passwordInput.type === 'password';
      passwordInput.type = isHidden ? 'text' : 'password';
      toggleBtn.textContent = isHidden ? '🙈' : '👁️';
      toggleBtn.setAttribute('title', isHidden ? 'Hide password' : 'Show password');
      toggleBtn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
      passwordInput.focus();
    });

    // Handle Cancel button
    const handleCancel = () => {
      overlay.remove();
      chrome.runtime.sendMessage({
        type: 'passwordPromptResponse',
        password: null
      });
    };

    // Event listeners
    okBtn.addEventListener('click', handleOk);
    cancelBtn.addEventListener('click', handleCancel);
    
    // Handle Enter key
    passwordInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleOk();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        handleCancel();
      }
    });

    // Handle clicking outside dialog
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        handleCancel();
      }
    });
  }

  createTotpDialog(message) {
    // Remove any existing dialog
    const existing = document.getElementById('password-manager-totp-dialog');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'password-manager-totp-dialog';
    overlay.style.cssText = `position: fixed; top:0; left:0; width:100%; height:100%; background: rgba(10,12,20,0.75); backdrop-filter: blur(2px); z-index: 999999; display:flex; align-items:center; justify-content:center; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;`;

    const dialog = document.createElement('div');
    dialog.style.cssText = `background:#0b0f16; border:1px solid #1f2937; border-radius:8px; padding:20px; box-shadow:0 10px 25px rgba(0,0,0,0.35); max-width:360px; width:90%; position:relative; color:#e5e7eb;`;
    dialog.innerHTML = `
      <div style="margin-bottom:16px;">
        <h3 style="margin:0 0 8px 0; color:#e5e7eb; font-size:16px; font-weight:600;">Two-Factor Authentication</h3>
        <p style="margin:0; color:#94a3b8; font-size:13px; line-height:1.4;">${message}</p>
      </div>
      <div style="margin-bottom:20px;">
        <input type="text" id="totp-input" placeholder="Enter 6-digit code" inputmode="numeric" maxlength="6"
               style="width:100%; padding:12px; border:1px solid #334155; background:#0f141d; color:#e5e7eb; border-radius:6px; font-size:16px; letter-spacing:4px; text-align:center; box-sizing:border-box; outline:none; transition:border-color 0.2s;" />
      </div>
      <div style="display:flex; gap:8px; justify-content:flex-end;">
        <button id="totp-cancel-btn" style="padding:8px 16px; border:1px solid #334155; background:#0b0f16; color:#e5e7eb; border-radius:6px; cursor:pointer; font-size:14px;">Cancel</button>
        <button id="totp-submit-btn" style="padding:8px 16px; border:1px solid #4f46e5; background:#0b0f16; color:#c7d2fe; border-radius:6px; cursor:pointer; font-size:14px; font-weight:600;">Verify</button>
      </div>
    `;

    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    const input = dialog.querySelector('#totp-input');
    const cancelBtn = dialog.querySelector('#totp-cancel-btn');
    const submitBtn = dialog.querySelector('#totp-submit-btn');
    input && input.focus();

    const close = () => overlay.remove();

    cancelBtn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'totpPromptResponse', code: null });
      close();
    });

    submitBtn.addEventListener('click', () => {
      const raw = (input.value || '').trim();
      const code = raw.replace(/\s+/g, '');
      if (!/^\d{6}$/.test(code)) {
        input.style.borderColor = '#ef4444';
        input.style.background = '#fee2e2';
        return;
      }
      chrome.runtime.sendMessage({ type: 'totpPromptResponse', code });
      close();
    });

    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        chrome.runtime.sendMessage({ type: 'totpPromptResponse', code: null });
        close();
      }
    });
  }

  handleFormSubmit(event) {
    const form = event.target.closest ? event.target.closest('form') : event.target;
    const loginForm = this.analyzeForm(form);
    
    if (loginForm && loginForm.usernameField && loginForm.passwordField) {
      const username = this.getFieldValue(loginForm.usernameField);
      const password = this.getFieldValue(loginForm.passwordField);
      
      if (username && password) {
        // Ask user if they want to save these credentials
        this.promptSaveCredentials({
          url: window.location.href,
          domain: this.domain,
          username: username,
          password: password,
          service_name: this.domain
        });
      }
    }
  }

  async promptSaveCredentials(credentials) {
    // Check if credentials already exist to avoid duplicates
    if (!this.credentials || !this.credentials.some(c => c.username === credentials.username)) {
      try {
        await chrome.runtime.sendMessage({
          type: 'saveCredentials',
          credentials: credentials
        });
        console.log('New credentials saved for', this.domain);
      } catch (error) {
        console.error('Error saving credentials:', error);
      }
    }
  }

  // Present credential selection UI when multiple credentials exist
  presentCredentialSelection() {
    // Only show when a login form exists on the page
    const hasLoginForms = this.forms && this.forms.size > 0;
    if (!hasLoginForms) return;

    if (this.credentialPickerActive) return; // already showing
    // Prevent repeated prompts within the same page lifecycle
    if (this.autoPromptShown) return;
    this.autoPromptShown = true;
    this.credentialPickerActive = true;
    try {
      this.showCredentialPicker(this.credentials || []);
    } catch (e) {
      console.warn('Failed to present credential picker:', e);
      this.credentialPickerActive = false;
    }
  }

  // In-page credential picker dialog (dark style consistent with other dialogs)
  showCredentialPicker(credentials = []) {
    try {
      const existing = document.getElementById('password-manager-credential-picker');
      if (existing) existing.remove();
    
      const overlay = document.createElement('div');
      overlay.id = 'password-manager-credential-picker';
      overlay.style.cssText = `position: fixed; top:0; left:0; width:100%; height:100%; background: rgba(16,18,27,.66); backdrop-filter: blur(2px); z-index: 999999; display:flex; align-items:center; justify-content:center; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;`;
    
      // Lock background scroll while the picker is open
      overlay.dataset.pmPrevOverflow = document.body.style.overflow || '';
      document.body.style.overflow = 'hidden';
    
      const dialog = document.createElement('div');
      dialog.style.cssText = `background:#0b0f16; border:1px solid #1f2937; border-radius:10px; padding:18px; box-shadow:0 16px 40px rgba(0,0,0,.35); max-width:480px; width:calc(100% - 32px); position:relative; transform:translateY(8px); opacity:0; transition:opacity .18s ease-out, transform .18s ease-out; color:#e5e7eb; box-sizing:border-box;`;
    
      const domainLabel = this.domain ? `<span style="color:#94a3b8;font-size:12px;text-transform:none;">${this.domain}</span>` : '';
      const headerHtml = `
        <div style="margin-bottom:12px;">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
            <h3 style="margin:0;color:#e5e7eb;font-size:16px;font-weight:600;text-transform:none;">Password Manager</h3>
            ${domainLabel}
          </div>
          <p style="margin:6px 0 0;color:#94a3b8;font-size:13px;">Select an account to fill for this site.</p>
        </div>`;
    
      const listContainer = document.createElement('div');
      listContainer.style.cssText = `max-height:300px; overflow-y:auto; overflow-x:hidden; border:1px solid #1f2937; background:#0f141d; border-radius:8px; padding:4px; box-sizing:border-box;`;
    
      let selectedIndex = -1;
    
      credentials.forEach((c, idx) => {
        const item = document.createElement('button');
        item.type = 'button';
        item.setAttribute('data-index', String(idx));
        const username = c.username || '(no username)';
        const meta = c.service_name || c.domain || c.url || '';
        item.style.cssText = `display:flex; align-items:center; justify-content:space-between; width:100%; text-align:left; background:#0b0f16; border:1px solid #1f2937; color:#e5e7eb; padding:10px; border-radius:6px; cursor:pointer; margin:6px 0; box-sizing:border-box;`;
        item.innerHTML = `
          <div style="display:flex; flex-direction:column; gap:2px; min-width:0;">
            <span style="font-size:14px; font-weight:600; color:#e5e7eb; overflow-wrap:anywhere; word-break:break-word;">${username}</span>
            <span style="font-size:12px; color:#94a3b8; overflow-wrap:anywhere; word-break:break-word;">${meta}</span>
          </div>
          <div aria-hidden="true" style="width:18px;height:18px;border:1px solid #334155;border-radius:50%; background:${selectedIndex===idx?'#4f46e5':'transparent'};"></div>`;
        item.addEventListener('click', () => {
          selectedIndex = idx;
          // Update visual selection state
          [...listContainer.querySelectorAll('button')].forEach((btn, bIdx) => {
            const indicator = btn.querySelector('div[aria-hidden="true"]');
            if (indicator) indicator.style.background = (bIdx === selectedIndex) ? '#4f46e5' : 'transparent';
            btn.style.borderColor = (bIdx === selectedIndex) ? '#4f46e5' : '#1f2937';
          });
        });
        listContainer.appendChild(item);
      });
    
      const actions = document.createElement('div');
      actions.style.cssText = `display:flex; gap:8px; justify-content:flex-end; margin-top:12px;`;
      const cancelBtn = document.createElement('button');
      cancelBtn.id = 'pm-cred-cancel';
      cancelBtn.textContent = 'Cancel';
      cancelBtn.style.cssText = `padding:8px 14px; border:1px solid #334155; background:#0b0f16; color:#e5e7eb; border-radius:6px; cursor:pointer; font-size:14px;`;
      const useBtn = document.createElement('button');
      useBtn.id = 'pm-cred-use';
      useBtn.textContent = 'Fill';
      useBtn.style.cssText = `padding:8px 14px; border:1px solid #4f46e5; background:#0b0f16; color:#c7d2fe; border-radius:6px; cursor:pointer; font-size:14px; font-weight:600;`;
    
      actions.appendChild(cancelBtn);
      actions.appendChild(useBtn);
    
      dialog.innerHTML = headerHtml;
      dialog.appendChild(listContainer);
      dialog.appendChild(actions);
      overlay.appendChild(dialog);
      document.body.appendChild(overlay);
    
      requestAnimationFrame(() => { dialog.style.transform = 'translateY(0)'; dialog.style.opacity = '1'; });
    
      const close = () => {
        // Restore page scroll
        document.body.style.overflow = overlay.dataset.pmPrevOverflow || '';
        overlay.remove();
        this.credentialPickerActive = false;
      };
      cancelBtn.addEventListener('click', () => close());
      overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
      document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { close(); } }, { once: true });
    
      useBtn.addEventListener('click', async () => {
        if (selectedIndex < 0 || selectedIndex >= credentials.length) {
          // No selection; highlight list
          listContainer.style.boxShadow = '0 0 0 2px rgba(239,68,68,0.45)';
          setTimeout(() => listContainer.style.boxShadow = 'none', 900);
          return;
        }
        let credential = { ...credentials[selectedIndex] };
        // Fetch password if missing
        if (!credential.password && credential.id) {
          try {
            const resp = await chrome.runtime.sendMessage({ type: 'getCredentialPassword', id: credential.id });
            if (resp && resp.type === 'passwordResult' && resp.success) {
              if (resp.password) {
                credential.password = resp.password;
              } else if (resp.encrypted_password && resp.nonce && resp.encryption_key) {
                const pw = await this.decryptHostPassword(resp.encrypted_password, resp.nonce, resp.encryption_key);
                if (pw) credential.password = pw;
              }
            }
          } catch (e) {
            console.warn('Failed to fetch password for selected credential:', e);
          }
        }
        // Fill all known forms with the selected credential
        for (let form of this.forms) {
          const loginForm = this.analyzeForm(form);
          if (loginForm) {
            this.fillForm(credential, loginForm);
          }
        }
        close();
      });
    } catch (e) {
      console.error('Credential picker failed:', e);
      this.credentialPickerActive = false;
    }
  }
}

// Initialize form detector when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new FormDetector();
  });
} else {
  new FormDetector();
}