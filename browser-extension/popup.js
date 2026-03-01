// Popup script for Password Manager extension
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
class PopupManager {
  constructor() {
    this.currentDomain = '';
    this.currentUrl = '';
    this.credentials = [];
    this.init();
  }

  async init() {
    await this.getCurrentTab();
    this.setupEventListeners();
    this.loadCredentials();
  }

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

  async getCurrentTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        this.currentUrl = tab.url;
        this.currentDomain = this.extractDomain(tab.url);
      }
    } catch (error) {
      console.error('Error getting current tab:', error);
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
    // Remove references to non-existent DOM elements
    // No generator, no open manager, no length input
  }

  async checkConnectionStatus() {
    // Removed connection status UI updates
    try {
      const response = await chrome.runtime.sendMessage({ type: 'checkAuthentication' });
      if (!response.connected) {
        this.showError('Cannot connect to Password Manager app. Please make sure it is running.');
      } else if (!response.authenticated) {
        if (response.error) this.showError(`Authentication error: ${response.error}`);
      }
    } catch (error) {
      console.error('Error checking connection status:', error);
      this.showError('Failed to check connection status.');
    }
  }

  async loadCredentials() {
    const container = document.getElementById('credentialsList');
    
    if (!this.currentDomain) {
      this.showEmptyState('No domain detected');
      return;
    }

    // Show loading state
    container.innerHTML = '<div class="loading">Loading credentials...</div>';

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'searchCredentials',
        domain: this.currentDomain,
        url: this.currentUrl
      });

      if (response.error) {
        this.showError(response.error);
        this.showEmptyState('Failed to load credentials');
        return;
      }

      this.credentials = response.credentials || [];
      this.displayCredentials();
    } catch (error) {
      console.error('Error loading credentials:', error);
      this.showError('Failed to load credentials');
      this.showEmptyState('Connection error');
    }
  }

  displayCredentials() {
    const container = document.getElementById('credentialsList');
    
    if (this.credentials.length === 0) {
      this.showEmptyState('No credentials found for this site');
      return;
    }

    container.innerHTML = '';
    
    this.credentials.forEach((credential, index) => {
      const item = document.createElement('div');
      item.className = 'credential-item';
      item.innerHTML = `
        <div class="credential-username">${this.escapeHtml(credential.username || 'No username')}</div>
        <div class="credential-domain">${this.escapeHtml(credential.service_name || this.currentDomain)}</div>
      `;
      
      item.addEventListener('click', () => {
        this.fillCredentials(credential);
      });
      
      container.appendChild(item);
    });
  }

  showEmptyState(message) {
    const container = document.getElementById('credentialsList');
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🔐</div>
        <div>${message}</div>
      </div>
    `;
  }

  async fillCredentials(credential) {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      // Fetch password from background before filling
      let fillData = { ...credential };
      try {
        const resp = await chrome.runtime.sendMessage({
          type: 'getCredentialPassword',
          id: credential.id
        });
        if (resp && resp.type === 'passwordResult' && resp.success) {
          if (resp.password) {
            fillData.password = resp.password;
          } else if (resp.encrypted_password && resp.nonce && resp.encryption_key) {
            const pw = await this.decryptHostPassword(resp.encrypted_password, resp.nonce, resp.encryption_key);
            if (pw) fillData.password = pw;
          }
        }
      } catch (e) {
        console.warn('Failed to retrieve password for credential:', e);
      }

      await chrome.tabs.sendMessage(tab.id, {
        type: 'fillCredentials',
        credentials: fillData
      });
      
      this.showSuccess('Credentials filled');
      
      // Close popup after a short delay
      setTimeout(() => {
        window.close();
      }, 1000);
    } catch (error) {
      console.error('Error filling credentials:', error);
      this.showError('Failed to fill credentials');
    }
  }

  async generatePassword() {
    // Removed: no longer used in UI
  }

  displayGeneratedPassword(password) {
    // Removed: no longer used in UI
  }

  async copyGeneratedPassword() {
    // Removed: no longer used in UI
  }

  async openPasswordManager() {
    // Removed: no longer used in UI
  }

  showError(message) {
    const errorElement = document.getElementById('errorMessage');
    const successElement = document.getElementById('successMessage');
    
    successElement.style.display = 'none';
    errorElement.textContent = message;
    errorElement.style.display = 'block';
    
    setTimeout(() => {
      errorElement.style.display = 'none';
    }, 5000);
  }

  showSuccess(message) {
    const errorElement = document.getElementById('errorMessage');
    const successElement = document.getElementById('successMessage');
    
    errorElement.style.display = 'none';
    successElement.textContent = message;
    successElement.style.display = 'block';
    
    setTimeout(() => {
      successElement.style.display = 'none';
    }, 3000);
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new PopupManager();
});