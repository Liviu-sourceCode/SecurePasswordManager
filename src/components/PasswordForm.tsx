import { useState, useEffect } from 'react';
import { PasswordEntry } from '../types';
import PasswordGenerator from './PasswordGenerator';
import { FaEye, FaEyeSlash } from 'react-icons/fa';

// Validation constants (matching backend)
const MAX_SERVICE_LENGTH = 100;
const MAX_USERNAME_LENGTH = 100;
const MAX_PASSWORD_LENGTH = 500;
const MAX_URL_LENGTH = 2000;
const MAX_NOTES_LENGTH = 1000;

interface ValidationErrors {
  service?: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
}

interface PasswordFormProps {
  entry?: PasswordEntry;
  onSave: (entry: Omit<PasswordEntry, 'id' | 'created_at' | 'updated_at'>) => void;
  onCancel: () => void;
}

export function PasswordForm({ entry, onSave, onCancel }: PasswordFormProps) {
  const [service, setService] = useState(entry?.service ?? '');
  const [username, setUsername] = useState(entry?.username ?? '');
  const [password, setPassword] = useState(entry?.password ?? '');
  const [url, setUrl] = useState(entry?.url ?? '');
  const [notes, setNotes] = useState(entry?.notes ?? '');
  const [errors, setErrors] = useState<ValidationErrors>({});
  const [showGenerator, setShowGenerator] = useState(true);
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    if (entry) {
      setService(entry.service);
      setUsername(entry.username);
      setPassword(entry.password);
      setUrl(entry.url ?? '');
      setNotes(entry.notes ?? '');
    } else {
      // Clear all fields when no entry is provided (new entry)
      setService('');
      setUsername('');
      setPassword('');
      setUrl('');
      setNotes('');
      setErrors({});
    }
  }, [entry]);

  // Security validation function
  const validateSecurity = (value: string): string | undefined => {
    // Check for suspicious patterns
    const suspiciousPatterns = [
      { pattern: /<[^>]*>/g, message: 'HTML tags are not allowed' },
      { pattern: /javascript:/gi, message: 'JavaScript URLs are not allowed' },
      { pattern: /vbscript:/gi, message: 'VBScript URLs are not allowed' },
      { pattern: /data:/gi, message: 'Data URLs are not allowed' },
      { pattern: /on\w+\s*=/gi, message: 'Event handlers are not allowed' },
      { pattern: /\.\.[\/\\]/g, message: 'Path traversal patterns are not allowed' },
      { pattern: /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, message: 'Control characters are not allowed' },
    ];

    for (const { pattern, message } of suspiciousPatterns) {
      if (pattern.test(value)) {
        return message;
      }
    }

    // Check for excessive length
    if (value.length > 10000) {
      return 'Input exceeds maximum allowed length';
    }

    return undefined;
  };

  const validateField = (field: string, value: string): string | undefined => {
    // First check security
    const securityError = validateSecurity(value);
    if (securityError) return securityError;

    switch (field) {
      case 'service':
        if (!value.trim()) return 'Service name is required';
        if (value.length > MAX_SERVICE_LENGTH) return `Service name must not exceed ${MAX_SERVICE_LENGTH} characters`;
        // Check for valid service name characters
        if (!/^[a-zA-Z0-9\s.\-_]+$/.test(value)) {
          return 'Service name contains invalid characters. Only letters, numbers, spaces, dots, hyphens, and underscores are allowed';
        }
        break;
      case 'username':
        if (!value.trim()) return 'Username is required';
        if (value.length > MAX_USERNAME_LENGTH) return `Username must not exceed ${MAX_USERNAME_LENGTH} characters`;
        break;
      case 'password':
        if (!value.trim()) return 'Password is required';
        if (value.length > MAX_PASSWORD_LENGTH) return `Password must not exceed ${MAX_PASSWORD_LENGTH} characters`;
        break;
      case 'url':
        if (value && value.length > MAX_URL_LENGTH) return `URL must not exceed ${MAX_URL_LENGTH} characters`;
        if (value && value.trim()) {
          // Enhanced URL validation
          const urlError = validateUrl(value);
          if (urlError) return urlError;
        }
        break;
      case 'notes':
        if (value && value.length > MAX_NOTES_LENGTH) return `Notes must not exceed ${MAX_NOTES_LENGTH} characters`;
        break;
    }
    return undefined;
  };

  const validateUrl = (url: string): string | undefined => {
    // Check for valid URL schemes
    const validSchemes = /^(https?|ftp|ftps):\/\//i;
    const domainPattern = /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}|[a-zA-Z]{2,}\.[a-zA-Z]{2,})(\/.*)?$/;
    
    if (!validSchemes.test(url) && !domainPattern.test(url)) {
      return 'Please enter a valid URL (e.g., example.com or https://example.com)';
    }

    // Check for suspicious URL patterns
    const suspiciousUrlPatterns = [
      /javascript:/gi,
      /data:/gi,
      /vbscript:/gi,
      /file:/gi,
      /[<>"']/g,
    ];

    for (const pattern of suspiciousUrlPatterns) {
      if (pattern.test(url)) {
        return 'URL contains potentially malicious content';
      }
    }

    return undefined;
  };

  const validateForm = (): boolean => {
    const newErrors: ValidationErrors = {};
    
    newErrors.service = validateField('service', service);
    newErrors.username = validateField('username', username);
    newErrors.password = validateField('password', password);
    newErrors.url = validateField('url', url);
    newErrors.notes = validateField('notes', notes);
    
    // Remove undefined errors
    Object.keys(newErrors).forEach(key => {
      if (!newErrors[key as keyof ValidationErrors]) {
        delete newErrors[key as keyof ValidationErrors];
      }
    });
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Input sanitization function
  const sanitizeInput = (input: string): string => {
    return input
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '') // Remove control characters
      .replace(/\uFEFF/g, '') // Remove BOM
      .replace(/[\u200B-\u200D\u2060]/g, '') // Remove zero-width characters
      .trim();
  };

  const handleFieldChange = (field: string, value: string) => {
    // Sanitize input first
    const sanitizedValue = sanitizeInput(value);
    
    // Clear error for this field when user starts typing
    if (errors[field as keyof ValidationErrors]) {
      setErrors(prev => ({ ...prev, [field]: undefined }));
    }
    
    switch (field) {
      case 'service': setService(sanitizedValue); break;
      case 'username': setUsername(sanitizedValue); break;
      case 'password': 
        setPassword(sanitizedValue);
        break;
      case 'url': setUrl(sanitizedValue); break;
      case 'notes': setNotes(sanitizedValue); break;
    }
  };

  const handlePasswordGenerated = (generatedPassword: string) => {
    setPassword(generatedPassword);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    onSave({
      service: service.trim(),
      username: username.trim(),
      password: password.trim(),
      url: url.trim() || undefined,
      notes: notes.trim() || undefined,
    });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4" autoComplete="off">
      <div className="form-row">
        <label htmlFor="service" className="password-form-label">
          Service
        </label>
        <input
          type="text"
          id="service"
          value={service}
          onChange={(e) => handleFieldChange('service', e.target.value)}
          placeholder="e.g., Gmail, Facebook, GitHub"
          required
          autoComplete="off"
          spellCheck={false}
          data-form-type="other"
          className="w-full px-6 py-3 border border-gray-600 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 bg-gray-800/50 text-white"
        />
        {errors.service && <p className="text-red-500 text-sm mt-1">{errors.service}</p>}
      </div>

      <div className="form-row">
        <label htmlFor="username" className="password-form-label">
          Username
        </label>
        <input
          type="text"
          id="username"
          value={username}
          onChange={(e) => handleFieldChange('username', e.target.value)}
          placeholder={!service.trim() ? "Complete Service first" : "Username or email"}
          disabled={!service.trim()}
          title={!service.trim() ? "Please complete Service first" : ""}
          autoComplete="off"
          spellCheck={false}
          data-form-type="other"
          className="w-full px-6 py-3 border border-gray-600 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 bg-gray-800/50 text-white disabled:opacity-50 disabled:cursor-not-allowed"
        />
        {errors.username && <p className="text-red-500 text-sm mt-1">{errors.username}</p>}
      </div>

      <div className="form-row">
        <label htmlFor="password" className="password-form-label">
          Password
        </label>
        <div className="relative w-full">
          <input
            type={showPassword ? "text" : "password"}
            id="password"
            value={password}
            onChange={(e) => handleFieldChange('password', e.target.value)}
            placeholder={!service.trim() || !username.trim() ? "Complete Service and Username first" : "Enter or generate password"}
            required
            disabled={!service.trim() || !username.trim()}
            title={!service.trim() || !username.trim() ? "Please complete Service and Username first" : ""}
            autoComplete="new-password"
            spellCheck={false}
            data-form-type="other"
            className="password-input w-full px-6 py-3 border border-gray-600 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 bg-gray-800/50 text-white disabled:opacity-50 disabled:cursor-not-allowed pr-12"
          />
          {password.length > 0 && (
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute p-2 text-gray-400 hover:text-white transition-colors rounded-full hover:bg-white/10 z-10"
              title={showPassword ? "Hide password" : "Show password"}
              style={{ 
                background: 'transparent', 
                border: 'none',
                position: 'absolute',
                right: '12px',
                top: '50%',
                transform: 'translateY(-50%)',
                left: 'auto',
                zIndex: 50
              }}
            >
              {showPassword ? <FaEyeSlash size={18} /> : <FaEye size={18} />}
            </button>
          )}
        </div>
        {errors.password && (
          <p className="text-red-500 text-sm mt-1">{errors.password}</p>
        )}
      </div>

      {showGenerator && (
        <PasswordGenerator 
          onPasswordGenerated={handlePasswordGenerated}
          initialPassword={password}
          onClose={() => setShowGenerator(false)}
          username={username}
          disabled={!service.trim() || !username.trim()}
        />
      )}

      {!showGenerator && (
        <div className="mb-4">
          <div className={`relative ${!service.trim() || !username.trim() ? 'opacity-60' : ''}`}>
            <button
              type="button"
              onClick={() => setShowGenerator(true)}
              disabled={!service.trim() || !username.trim()}
              title={!service.trim() || !username.trim() ? "Please complete Service and Username first" : "Show Generator"}
              className="btn btn-ghost text-blue-400 hover:text-blue-300 disabled:opacity-50 disabled:cursor-not-allowed disabled:text-gray-500 disabled:border-gray-600 disabled:bg-gray-800/30"
            >
              + Show Generator
            </button>
            {(!service.trim() || !username.trim()) && (
              <div className="absolute inset-0 bg-gray-900/20 rounded-lg pointer-events-none"></div>
            )}
          </div>
          {(!service.trim() || !username.trim()) && (
            <div className="flex items-center mt-2">
              <span className="text-yellow-500 mr-2">⚠️</span>
              <p className="text-gray-400 text-sm">Complete Service and Username to enable generator</p>
            </div>
          )}
        </div>
      )}

      <div className="form-row">
        <label htmlFor="url" className="password-form-label">
          URL (optional)
        </label>
        <input
          type="url"
          id="url"
          value={url}
          onChange={(e) => handleFieldChange('url', e.target.value)}
          placeholder={!service.trim() || !username.trim() ? "Complete Service and Username first" : "https://example.com"}
          disabled={!service.trim() || !username.trim()}
          title={!service.trim() || !username.trim() ? "Please complete Service and Username first" : ""}
          autoComplete="off"
          spellCheck={false}
          data-form-type="other"
          className="w-full px-6 py-3 border border-gray-600 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 bg-gray-800/50 text-white disabled:opacity-50 disabled:cursor-not-allowed"
        />
        {errors.url && <p className="text-red-500 text-sm mt-1">{errors.url}</p>}
      </div>

      <div className="form-row">
  <label htmlFor="notes" className="password-form-label">
    Notes (optional)
  </label>
  <textarea
    id="notes"
    value={notes}
    onChange={(e) => handleFieldChange('notes', e.target.value)}
    placeholder={!service.trim() || !username.trim() ? "Complete Service and Username first" : "Additional notes, security questions, etc."}
    rows={3}
    disabled={!service.trim() || !username.trim()}
    title={!service.trim() || !username.trim() ? "Please complete Service and Username first" : ""}
    autoComplete="off"
    spellCheck={false}
    data-form-type="other"
    className="w-full px-6 py-3 border border-gray-600 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 resize-none bg-gray-800/50 text-white disabled:opacity-50 disabled:cursor-not-allowed"
  />
  {errors.notes && <p className="text-red-500 text-sm mt-1">{errors.notes}</p>}
</div>

      <div className="controls">
        <button
          type="button"
          onClick={onCancel}
          className="btn btn-ghost"
        >
          Cancel
        </button>
        <button
          type="submit"
          className="btn btn-primary"
        >
          Save
        </button>
      </div>
    </form>
  );
}