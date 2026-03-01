// Injected script for Password Manager extension
// This script runs in the page context and can interact with page JavaScript

(function() {
  'use strict';

  // Prevent multiple injections
  if (window.passwordManagerInjected) {
    return;
  }
  window.passwordManagerInjected = true;

  // Enhanced form detection for complex web applications
  class AdvancedFormDetector {
    constructor() {
      this.setupFormInterception();
      this.setupPasswordFieldEnhancement();
    }

    setupFormInterception() {
      // Intercept form submissions to catch credentials
      const originalSubmit = HTMLFormElement.prototype.submit;
      HTMLFormElement.prototype.submit = function() {
        window.postMessage({
          type: 'PM_FORM_SUBMIT',
          formData: this.extractFormData()
        }, '*');
        return originalSubmit.apply(this, arguments);
      };

      // Intercept fetch requests that might be login attempts
      const originalFetch = window.fetch;
      window.fetch = function(url, options) {
        if (options && options.method === 'POST' && options.body) {
          try {
            let body = options.body;
            if (typeof body === 'string') {
              // Try to parse as JSON or form data
              try {
                const jsonData = JSON.parse(body);
                if (jsonData.username || jsonData.email || jsonData.password) {
                  window.postMessage({
                    type: 'PM_FETCH_LOGIN',
                    url: url,
                    credentials: jsonData
                  }, '*');
                }
              } catch (e) {
                // Try to parse as URL encoded
                const params = new URLSearchParams(body);
                const credentials = {};
                for (let [key, value] of params) {
                  if (key.toLowerCase().includes('user') || 
                      key.toLowerCase().includes('email') ||
                      key.toLowerCase().includes('login')) {
                    credentials.username = value;
                  }
                  if (key.toLowerCase().includes('pass')) {
                    credentials.password = value;
                  }
                }
                if (credentials.username && credentials.password) {
                  window.postMessage({
                    type: 'PM_FETCH_LOGIN',
                    url: url,
                    credentials: credentials
                  }, '*');
                }
              }
            }
          } catch (e) {
            // Ignore parsing errors
          }
        }
        return originalFetch.apply(this, arguments);
      };
    }

    setupPasswordFieldEnhancement() {
      // Add visual indicators to password fields
      const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          if (mutation.type === 'childList') {
            mutation.addedNodes.forEach((node) => {
              if (node.nodeType === Node.ELEMENT_NODE) {
                this.enhancePasswordFields(node);
              }
            });
          }
        });
      });

      observer.observe(document.body, {
        childList: true,
        subtree: true
      });

      // Enhance existing fields
      this.enhancePasswordFields(document.body);
    }

    enhancePasswordFields(container) {
      const passwordFields = container.querySelectorAll('input[type="password"]');
      
      passwordFields.forEach(field => {
        if (field.dataset.pmEnhanced) return;
        
        field.dataset.pmEnhanced = 'true';
        
        // Add focus/blur handlers for better detection
        field.addEventListener('focus', () => {
          window.postMessage({
            type: 'PM_PASSWORD_FOCUS',
            fieldInfo: {
              id: field.id,
              name: field.name,
              placeholder: field.placeholder,
              form: field.form ? field.form.action : null
            }
          }, '*');
        });

        // Detect password strength as user types
        field.addEventListener('input', () => {
          if (field.value.length > 0) {
            const strength = this.calculatePasswordStrength(field.value);
            this.showPasswordStrength(field, strength);
          }
        });
      });
    }

    calculatePasswordStrength(password) {
      let score = 0;
      let feedback = [];

      // Length check
      if (password.length >= 8) score += 1;
      else feedback.push('Use at least 8 characters');

      if (password.length >= 12) score += 1;

      // Character variety
      if (/[a-z]/.test(password)) score += 1;
      else feedback.push('Add lowercase letters');

      if (/[A-Z]/.test(password)) score += 1;
      else feedback.push('Add uppercase letters');

      if (/[0-9]/.test(password)) score += 1;
      else feedback.push('Add numbers');

      if (/[^A-Za-z0-9]/.test(password)) score += 1;
      else feedback.push('Add special characters');

      // Common patterns (reduce score)
      if (/(.)\1{2,}/.test(password)) score -= 1; // Repeated characters
      if (/123|abc|qwe/i.test(password)) score -= 1; // Sequential patterns

      const strength = Math.max(0, Math.min(5, score));
      const levels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'];
      
      return {
        score: strength,
        level: levels[strength],
        feedback: feedback
      };
    }

    showPasswordStrength(field, strength) {
      // Remove existing indicator
      const existingIndicator = field.parentNode.querySelector('.pm-strength-indicator');
      if (existingIndicator) {
        existingIndicator.remove();
      }

      // Create strength indicator
      const indicator = document.createElement('div');
      indicator.className = 'pm-strength-indicator';
      indicator.style.cssText = `
        position: absolute;
        right: 30px;
        top: 50%;
        transform: translateY(-50%);
        font-size: 10px;
        padding: 2px 6px;
        border-radius: 3px;
        z-index: 10001;
        pointer-events: none;
      `;

      const colors = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#16a34a', '#15803d'];
      indicator.style.backgroundColor = colors[strength.score];
      indicator.style.color = 'white';
      indicator.textContent = strength.level;

      // Position relative to field
      if (field.parentNode.style.position === 'static') {
        field.parentNode.style.position = 'relative';
      }

      field.parentNode.appendChild(indicator);

      // Remove after 3 seconds
      setTimeout(() => {
        if (indicator.parentNode) {
          indicator.remove();
        }
      }, 3000);
    }
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      new AdvancedFormDetector();
    });
  } else {
    new AdvancedFormDetector();
  }

  // Listen for messages from content script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    switch (event.data.type) {
      case 'PM_FILL_FORM':
        // Handle form filling requests
        break;
      case 'PM_GENERATE_PASSWORD':
        // Handle password generation requests
        break;
    }
  });

  console.log('Password Manager injected script loaded');
})();