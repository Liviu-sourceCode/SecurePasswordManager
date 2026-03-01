// Background service worker for Password Manager extension
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

  // Load log level from managed or local storage (enterprise can set managed policy)
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
const NATIVE_APP_NAME = 'com.passwordmanager.native';

// Log the extension ID for debugging
console.log('Extension ID:', chrome.runtime.id);

class NativeMessagingService {
  constructor() {
    this.port = null;
    this.sessionToken = null;
    this.encryptionKey = null; // base64 session key from host
    this.isConnected = false;
    this.cachedMasterPassword = null;
    this.passwordCacheExpiry = null;
    // Keep master password in memory for longer (session-level), not persisted
    this.passwordCacheTimeout = 60 * 60 * 1000; // 60 minutes
    this.keepAliveInterval = null;
  }

  // Connect to native messaging host
  connect() {
    if (this.port) {
      this.port.disconnect();
    }

    try {
      console.log('Attempting to connect to native messaging host:', NATIVE_APP_NAME);
      this.port = chrome.runtime.connectNative(NATIVE_APP_NAME);
      this.setupPortListeners();
      this.isConnected = true;
      this.reconnectAttempts = 0; // Reset retry counter on successful connection
      console.log('Successfully connected to native messaging host');
    } catch (error) {
      console.error('Failed to connect to native messaging host:', error);
      console.error('Make sure the Tauri application is running and the native messaging host is properly configured');
      this.isConnected = false;
    }
  }

  setupPortListeners() {
    this.port.onMessage.addListener((message) => {
      console.log('Received from native app:', message);
      this.handleNativeMessage(message);
    });

    this.port.onDisconnect.addListener(() => {
      console.log('Disconnected from native messaging host');
      this.isConnected = false;
      this.sessionToken = null;
      
      if (chrome.runtime.lastError) {
        console.error('Native messaging error:', chrome.runtime.lastError.message);
        
        // Only attempt to reconnect if we haven't exceeded retry limit
        this.reconnectAttempts = (this.reconnectAttempts || 0) + 1;
        if (this.reconnectAttempts < 5) {
          setTimeout(() => {
            console.log(`Attempting to reconnect to native messaging host... (attempt ${this.reconnectAttempts}/5)`);
            this.connect();
          }, 3000 * this.reconnectAttempts); // Exponential backoff
        } else {
          console.error('Max reconnection attempts reached. Please check if the Tauri application is running properly.');
        }
      }
    });
  }

  // Send message to native app
  sendMessage(message) {
    if (!this.isConnected || !this.port) {
      console.error('Not connected to native messaging host');
      return Promise.reject(new Error('Not connected'));
    }

    return new Promise((resolve, reject) => {
      const messageId = Date.now().toString();
      const messageWithId = { ...message, id: messageId };

      // Store resolver for this message
      this.pendingMessages = this.pendingMessages || new Map();
      this.pendingMessages.set(messageId, { resolve, reject });

      // Set timeout for message (longer timeout for credential operations)
      setTimeout(() => {
        if (this.pendingMessages.has(messageId)) {
          this.pendingMessages.delete(messageId);
          reject(new Error('Message timeout - operation took longer than 30 seconds'));
        }
      }, 30000); // 30 second timeout

      this.port.postMessage(messageWithId);
    });
  }

  handleNativeMessage(message) {
    console.log('Received native message:', message);
    
    if (message.id && this.pendingMessages && this.pendingMessages.has(message.id)) {
      const { resolve } = this.pendingMessages.get(message.id);
      this.pendingMessages.delete(message.id);
      console.log('Resolving pending message with ID:', message.id);
      resolve(message);
      return;
    }

    // Handle specific message types
    switch (message.type) {
      case 'authenticationResult':
        if (message.success) {
          this.sessionToken = message.session_token;
          this.encryptionKey = message.encryption_key || null;
          console.log('Authentication successful');
        } else {
          console.error('Authentication failed:', message.error);
        }
        break;
      
      case 'passwordResult':
        // Handle password generation result
        break;
      
      case 'credentialsResult':
        // Handle credential search result
        break;
    }
  }

  // Password cache management
  cacheMasterPassword(password) {
    console.log('Master password stored in memory briefly');
    this.cachedMasterPassword = password;
    this.passwordCacheExpiry = Date.now() + this.passwordCacheTimeout;
    
    // Clear cache after timeout
    setTimeout(() => {
      console.log('Password cache expired');
      this.clearPasswordCache();
    }, this.passwordCacheTimeout);
  }

  async getMasterPassword() {
    const inMemory = this.getCachedMasterPassword();
    if (inMemory) return inMemory;
    // No persistent storage of master password; prompt if not cached
    return null;
  }

  getCachedMasterPassword() {
    if (this.cachedMasterPassword && this.passwordCacheExpiry && Date.now() < this.passwordCacheExpiry) {
      console.log('Using cached master password');
      return this.cachedMasterPassword;
    }
    return null;
  }

  clearPasswordCache() {
    this.cachedMasterPassword = null;
    this.passwordCacheExpiry = null;
  }

  // Authenticate with the native app
  async authenticate() {
    if (!this.isConnected) {
      this.connect();
    }

    try {
      const response = await this.sendMessage({
        type: 'Authenticate',
        extension_id: chrome.runtime.id,
        origin: 'chrome-extension://' + chrome.runtime.id
      });

      if (response.type === 'authenticationResult' && response.success) {
        this.sessionToken = response.session_token;
        this.encryptionKey = response.encryption_key || null;
        // Start keep-alive pings to prevent auto-lock and maintain session
        this.startKeepAlive();
        return true;
      }
      return false;
    } catch (error) {
      console.error('Authentication error:', error);
      return false;
    }
  }

  // Periodically ping host to keep session active and prevent auto-lock
  startKeepAlive() {
    if (this.keepAliveInterval) return;
    this.keepAliveInterval = setInterval(() => {
      if (!this.isConnected) return;
      try {
        this.sendMessage({ type: 'GetVaultStatus', session_token: this.sessionToken }).catch(() => {});
      } catch {}
    }, 2 * 60 * 1000); // every 2 minutes
  }

  // Search for credentials by domain
  async searchCredentials(domain, url) {
    try {
      if (!this.sessionToken) {
        const authenticated = await this.authenticate();
        if (!authenticated) {
          throw new Error('Authentication failed');
        }
      }
    } catch (error) {
      console.error('Error during authentication in searchCredentials:', error);
      throw error;
    }

    const response = await this.sendMessage({
      type: 'SearchCredentials',
      domain: domain,
      url: url,
      session_token: this.sessionToken
    });

    // Check if vault unlock is required
    if (response.type === 'unlockRequired') {
      console.log('Vault unlock required for credential search:', response.message);
      // First attempt device unlock (DPAPI) without prompting
      try {
        const du = await this.sendMessage({ type: 'UnlockWithDeviceKey' });
        if (du && du.type === 'unlockResult' && du.success) {
          console.log('Device unlock succeeded. Retrying credential search.');
          const retry = await this.sendMessage({
            type: 'SearchCredentials',
            domain: domain,
            url: url,
            session_token: this.sessionToken
          });
          return retry;
        } else {
          console.log('Device unlock unavailable or failed:', du && du.error);
        }
      } catch (e) {
        console.log('Device unlock attempt errored:', e.message);
      }
      
      // Try to use cached master password first
      let masterPassword = await this.getMasterPassword();
      
      if (!masterPassword) {
        console.log('No cached password found, prompting user');
        // Only prompt if no cached password available
        masterPassword = await this.promptForMasterPassword(response.message);
        if (!masterPassword) {
          throw new Error('Master password required to search credentials');
        }
        
        // Cache the password for future use
        console.log('Caching master password temporarily');
        this.cacheMasterPassword(masterPassword);
      } else {
        console.log('Using cached password for automatic unlock');
      }

      // Search with password
      console.log('Sending SearchCredentialsWithPassword with cached/entered password');
      try {
        const result = await this.sendMessage({
          type: 'SearchCredentialsWithPassword',
          domain: domain,
          url: url,
          master_password: masterPassword,
          session_token: this.sessionToken
        });
        // Handle possible TOTP enforcement from native app
        if (result && result.type === 'credentialsResult') {
          if (result.success) {
            console.log('SearchCredentialsWithPassword completed successfully');
            console.log('Credentials found:', result.credentials ? result.credentials.length : 0);
            // Store device unlock key for future sessions
            try {
              const en = await this.sendMessage({ type: 'EnableDeviceUnlock' });
              if (en && en.type === 'unlockResult' && en.success) {
                console.log('Device unlock enabled successfully.');
              } else {
                console.log('EnableDeviceUnlock failed:', en && en.error);
              }
            } catch (e) {
              console.log('EnableDeviceUnlock error:', e.message);
            }
            return result;
          } else {
            const errMsg = (result.error || '').toLowerCase();
            if (errMsg.includes('totp required')) {
              console.log('TOTP required, prompting user for code');
              const code = await this.promptForTotpCode('Two-factor authentication required. Enter your 6-digit TOTP code.');
              if (!code) {
                throw new Error('TOTP code required to continue');
              }
              const totpResp = await this.verifyTotp(code);
              if (totpResp && totpResp.type === 'totpResult' && totpResp.success) {
                console.log('TOTP verified. Retrying credential search with provided password.');
                const retry = await this.sendMessage({
                  type: 'SearchCredentialsWithPassword',
                  domain: domain,
                  url: url,
                  master_password: masterPassword,
                  session_token: this.sessionToken
                });
                if (retry && retry.type === 'credentialsResult') {
                  if (retry.success) {
                    console.log('SearchCredentialsWithPassword completed successfully after TOTP');
                    console.log('Credentials found:', retry.credentials ? retry.credentials.length : 0);
                    // Store device unlock key for future sessions
                    try {
                      const en = await this.sendMessage({ type: 'EnableDeviceUnlock' });
                      if (en && en.type === 'unlockResult' && en.success) {
                        console.log('Device unlock enabled successfully.');
                      } else {
                        console.log('EnableDeviceUnlock failed:', en && en.error);
                      }
                    } catch (e) {
                      console.log('EnableDeviceUnlock error:', e.message);
                    }
                    return retry;
                  }
                  const retryErr = retry.error || 'Unknown error after TOTP verification';
                  throw new Error(retryErr);
                }
                throw new Error('Unexpected response after TOTP verification');
              }
              const terr = (totpResp && totpResp.error) ? totpResp.error : 'TOTP verification failed';
              throw new Error(terr);
            }
            if (errMsg.includes('invalid password')) {
              console.log('Invalid password reported. Clearing cached password.');
              this.clearPasswordCache();
            }
            // Return the error result to caller for handling
            return result;
          }
        }
        // Unexpected type, return as-is
        return result;
      } catch (error) {
        const lower = (error && error.message ? error.message : '').toLowerCase();
        console.log('SearchCredentialsWithPassword failed:', error.message);
        
        // Handle timeout errors specifically
        if (lower.includes('timeout')) {
          console.log('Operation timed out - this may indicate the native app is busy or unresponsive');
          // Try to reconnect for next attempt
          if (!this.isConnected) {
            console.log('Attempting to reconnect after timeout...');
            this.connect();
          }
        }
        
        // Only clear caches if the password itself is invalid
        if (this.getCachedMasterPassword() === masterPassword) {
          if (lower.includes('invalid password')) {
            console.log('Invalid password detected - clearing caches');
            this.clearPasswordCache();
          } else if (lower.includes('totp')) {
            console.log('MFA required - keeping cached password');
          }
        }
        throw error;
      }
    }

    return response;
  }

  // Prompt user for master password
  async promptForMasterPassword(message) {
    return new Promise((resolve) => {
      // Store the resolve function for later use
      this.passwordPromptResolve = resolve;
      
      // Set a timeout to avoid hanging indefinitely
      const timeout = setTimeout(() => {
        if (this.passwordPromptResolve) {
          console.log('Password prompt timeout');
          this.passwordPromptResolve(null);
          this.passwordPromptResolve = null;
        }
      }, 60000); // 60 second timeout
      
      // Store timeout reference to clear it when password is received
      this.passwordPromptTimeout = timeout;
      
      // Send message to content script to show password prompt
      chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'showPasswordPrompt',
            message: message
          }, (response) => {
            if (chrome.runtime.lastError) {
              console.log('Content script not available, trying direct prompt');
              // Don't resolve immediately, wait for the timeout or manual response
            }
          });
        } else {
          console.log('No active tab found');
          clearTimeout(timeout);
          resolve(null);
        }
      });
    });
  }

  // Handle password response from content script
  handlePasswordPromptResponse(password) {
    if (this.passwordPromptResolve) {
      // Clear the timeout
      if (this.passwordPromptTimeout) {
        clearTimeout(this.passwordPromptTimeout);
        this.passwordPromptTimeout = null;
      }
      
      this.passwordPromptResolve(password);
      this.passwordPromptResolve = null;
    }
  }

  // Handle TOTP prompt response
  handleTotpPromptResponse(code) {
    if (this.totpPromptResolve) {
      if (this.totpPromptTimeout) {
        clearTimeout(this.totpPromptTimeout);
        this.totpPromptTimeout = null;
      }
      this.totpPromptResolve(code);
      this.totpPromptResolve = null;
    }
  }

  // Generate password
  async generatePassword(options = {}) {
    if (!this.sessionToken) {
      const authenticated = await this.authenticate();
      if (!authenticated) {
        throw new Error('Authentication failed');
      }
    }

    const defaultOptions = {
      length: 16,
      include_uppercase: true,
      include_lowercase: true,
      include_numbers: true,
      include_symbols: true
    };

    return this.sendMessage({
      type: 'GeneratePassword',
      options: { ...defaultOptions, ...options },
      session_token: this.sessionToken
    });
  }

  // Save credentials
  async saveCredentials(credentials) {
    if (!this.sessionToken) {
      const authenticated = await this.authenticate();
      if (!authenticated) {
        throw new Error('Authentication failed');
      }
    }

    // Align payload with native host schema
    const payload = {
      type: 'SaveCredential',
      domain: credentials.domain,
      username: credentials.username,
      password: credentials.password,
      url: credentials.url,
      session_token: this.sessionToken
    };
    return this.sendMessage(payload);
  }

  // Retrieve password for a credential by ID
  async getPassword(credentialId) {
    if (!this.sessionToken) {
      const authenticated = await this.authenticate();
      if (!authenticated) {
        throw new Error('Authentication failed');
      }
    }

    let response = await this.sendMessage({
      type: 'GetPassword',
      credential_id: credentialId,
      session_token: this.sessionToken
    });

    if (response && response.type === 'unlockRequired') {
      console.log('Vault unlock required to retrieve password');
      // Attempt device unlock first to avoid prompting
      try {
        const du = await this.sendMessage({ type: 'UnlockWithDeviceKey' });
        if (du && du.type === 'unlockResult' && du.success) {
          console.log('Device unlock succeeded. Retrying password fetch.');
          response = await this.sendMessage({
            type: 'GetPassword',
            credential_id: credentialId,
            session_token: this.sessionToken
          });
        } else {
          console.log('Device unlock unavailable or failed:', du && du.error);
        }
      } catch (e) {
        console.log('Device unlock attempt errored:', e.message);
      }
      if (response && response.type !== 'passwordResult') {
        let masterPassword = await this.getMasterPassword();
        if (!masterPassword) {
          masterPassword = await this.promptForMasterPassword(response.message);
          if (!masterPassword) {
            throw new Error('Master password required to retrieve password');
          }
          this.cacheMasterPassword(masterPassword);
        }
        // Attempt to unlock vault first
        const unlock = await this.sendMessage({
          type: 'UnlockVault',
          master_password: masterPassword,
          session_token: this.sessionToken
        });
        if (!(unlock && unlock.type === 'unlockResult' && unlock.success)) {
          const err = (unlock && unlock.error) ? unlock.error : 'Failed to unlock vault';
          throw new Error(err);
        }
        // Persist device unlock key for future operations
        try {
          const en = await this.sendMessage({ type: 'EnableDeviceUnlock' });
          if (en && en.type === 'unlockResult' && en.success) {
            console.log('Device unlock enabled successfully.');
          } else {
            console.log('EnableDeviceUnlock failed:', en && en.error);
          }
        } catch (e) {
          console.log('EnableDeviceUnlock error:', e.message);
        }
        // Retry fetching password after unlock
        response = await this.sendMessage({
          type: 'GetPassword',
          credential_id: credentialId,
          session_token: this.sessionToken
        });
      }
    }
    // Attach encryption key for content script decryption
    if (response && response.type === 'passwordResult') {
      response.encryption_key = this.encryptionKey || null;
    }
    return response;
  }
  // Prompt user for TOTP code
  async promptForTotpCode(message) {
    return new Promise((resolve) => {
      this.totpPromptResolve = resolve;
      const timeout = setTimeout(() => {
        if (this.totpPromptResolve) {
          console.log('TOTP prompt timeout');
          this.totpPromptResolve(null);
          this.totpPromptResolve = null;
        }
      }, 30000);
      this.totpPromptTimeout = timeout;

      chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'showTotpPrompt',
            message: message
          }, (response) => {
            if (chrome.runtime.lastError) {
              console.log('Content script not available for TOTP prompt');
            }
          });
        } else {
          console.log('No active tab found for TOTP prompt');
          clearTimeout(timeout);
          resolve(null);
        }
      });
    });
  }

  // Handle TOTP prompt response
  handleTotpPromptResponse(code) {
    if (this.totpPromptTimeout) {
      clearTimeout(this.totpPromptTimeout);
      this.totpPromptTimeout = null;
    }
    if (this.totpPromptResolve) {
      this.totpPromptResolve(code);
      this.totpPromptResolve = null;
    }
  }

  // Verify TOTP via native host
  async verifyTotp(code) {
    return this.sendMessage({
      type: 'VerifyTotp',
      code: code,
      session_token: this.sessionToken
    });
  }
}

// Global instance
const nativeMessaging = new NativeMessagingService();

// Extension event listeners
chrome.runtime.onInstalled.addListener(() => {
  console.log('Password Manager extension installed');
});

chrome.runtime.onStartup.addListener(() => {
  console.log('Password Manager extension started');
  nativeMessaging.connect();
});

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('Received message:', message);

  switch (message.type) {
    case 'searchCredentials':
      nativeMessaging.searchCredentials(message.domain, message.url)
        .then(sendResponse)
        .catch(error => sendResponse({ error: error.message }));
      return true; // Keep message channel open for async response

    case 'getCredentialPassword':
      nativeMessaging.getPassword(message.id)
        .then(sendResponse)
        .catch(error => sendResponse({ error: error.message }));
      return true;

    case 'generatePassword':
      nativeMessaging.generatePassword(message.options)
        .then(sendResponse)
        .catch(error => sendResponse({ error: error.message }));
      return true;

    case 'saveCredentials':
      nativeMessaging.saveCredentials(message.credentials)
        .then(sendResponse)
        .catch(error => sendResponse({ error: error.message }));
      return true;

    case 'getConnectionStatus':
      sendResponse({ 
        connected: nativeMessaging.isConnected,
        authenticated: !!nativeMessaging.sessionToken
      });
      break;

    case 'checkAuthentication':
      // Trigger authentication and return status
      nativeMessaging.authenticate()
        .then(success => {
          sendResponse({ 
            connected: nativeMessaging.isConnected,
            authenticated: success && !!nativeMessaging.sessionToken
          });
        })
        .catch(error => {
          console.error('Authentication check error:', error);
          sendResponse({ 
            connected: nativeMessaging.isConnected,
            authenticated: false,
            error: error.message
          });
        });
      return true; // Keep message channel open for async response

    case 'passwordPromptResponse':
      // Accept plaintext password from content script dialog
      const password = message.password || null;
      // Cache in memory for faster reuse
      nativeMessaging.cacheMasterPassword(password);
      nativeMessaging.handlePasswordPromptResponse(password);
      sendResponse({ success: true });
      break;

    case 'totpPromptResponse':
      nativeMessaging.handleTotpPromptResponse(message.code || null);
      sendResponse({ success: true });
      break;

    default:
      console.warn('Unknown message type:', message.type);
  }
});

// Handle tab updates to detect navigation
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Extract domain from URL
    const domain = extractDomain(tab.url);
    
    // Notify content script about page load
    chrome.tabs.sendMessage(tabId, {
      type: 'pageLoaded',
      url: tab.url,
      domain: domain
    }).catch(() => {
      // Ignore errors if content script is not ready
    });

    // Proactively search for credentials for this domain
    if (domain && nativeMessaging.isConnected) {
      proactiveCredentialSearch(tabId, domain, tab.url);
    }
  }
});

// Helper function to extract domain from URL
function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (error) {
    return '';
  }
}

// Proactively search for credentials and cache them
async function proactiveCredentialSearch(tabId, domain, url) {
  try {
    console.log(`Starting proactive credential search for domain: ${domain}`);
    
    if (!nativeMessaging.isConnected) {
      console.log('Native messaging not connected, attempting to connect...');
      nativeMessaging.connect();
      // Wait a bit for connection to establish
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    const response = await nativeMessaging.searchCredentials(domain, url);
    
    if (response && response.type === 'credentialsResult' && response.credentials) {
      console.log(`Proactively found ${response.credentials.length} credentials for ${domain}`);
      
      // Send credentials to content script for immediate auto-fill
      chrome.tabs.sendMessage(tabId, {
        type: 'credentialsFound',
        domain: domain,
        credentials: response.credentials
      }).catch((error) => {
        console.log('Content script not ready yet, credentials will be available when it loads');
      });
    } else {
      console.log(`No credentials found for domain: ${domain}`);
    }
  } catch (error) {
    console.error('Proactive credential search failed for domain', domain, ':', error);
  }
}

// Initialize connection on startup
nativeMessaging.connect();

(function ensureMessageSupport(){
  // Add a minimal handler to forward proactive multiple credentials to content
  try {
    if (!chrome.runtime.onMessage.hasMultipleForwardHook) {
      chrome.runtime.onMessage.hasMultipleForwardHook = true;
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message && message.type === 'forwardMultipleCredentials' && Array.isArray(message.credentials)) {
          // Relay to tab's content script
          const tabId = sender.tab?.id;
          if (tabId) {
            chrome.tabs.sendMessage(tabId, { type: 'credentialsFound', credentials: message.credentials });
            sendResponse?.({ ok: true });
          }
        }
      });
    }
  } catch(_) {}
})();