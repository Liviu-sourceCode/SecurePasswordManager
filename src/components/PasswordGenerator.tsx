import { useState, useEffect } from 'react';
import { analyzePasswordStrength, getStrengthColor, getStrengthLabel } from '../utils/passwordStrength';

interface PasswordGeneratorProps {
  onPasswordGenerated: (password: string) => void;
  initialPassword?: string;
  onClose?: () => void;
  username?: string;
  disabled?: boolean;
}

interface GeneratorOptions {
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
  excludeSimilar: boolean;
}





const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';
// Characters that look similar and can be confusing when reading passwords
const CONFUSING_CHARS = 'il1Lo0O';

export function PasswordGenerator({ onPasswordGenerated, initialPassword = '', onClose, username, disabled = false }: PasswordGeneratorProps) {
  const [password, setPassword] = useState(initialPassword);
  const [options, setOptions] = useState<GeneratorOptions>({
    length: 16,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSymbols: true,
    excludeSimilar: false,
  });

  const generateCharacterSet = (): string => {
    let charset = '';
    if (options.includeUppercase) charset += UPPERCASE;
    if (options.includeLowercase) charset += LOWERCASE;
    if (options.includeNumbers) charset += NUMBERS;
    if (options.includeSymbols) charset += SYMBOLS;
    
    if (options.excludeSimilar) {
      charset = charset.split('').filter(char => !CONFUSING_CHARS.includes(char)).join('');
    }
    
    return charset;
  };

  const generatePassword = (): string => {
    const charset = generateCharacterSet();
    if (charset.length === 0) return '';
    
    let result = '';
    const array = new Uint8Array(options.length);
    crypto.getRandomValues(array);
    
    for (let i = 0; i < options.length; i++) {
      result += charset[array[i] % charset.length];
    }
    
    return result;
  };





  const handleGenerate = () => {
    const newPassword = generatePassword();
    setPassword(newPassword);
    onPasswordGenerated(newPassword);
  };

  const strengthResult = password ? analyzePasswordStrength(password, username ? { username } : undefined) : null;



  const handleClear = () => {
    setPassword('');
    onPasswordGenerated('');
  };

  useEffect(() => {
    if (initialPassword !== password) {
      setPassword(initialPassword);
    }
  }, [initialPassword]);

  return (
    <div className="password-generator">
      <div className="generator-header">
        <h3>Generator</h3>
        <div className="flex gap-2">
          {onClose && (
            <button
              type="button"
              onClick={onClose}
              className="close-btn"
              title="Close Generator"
              aria-label="Close Generator"
            >
              ×
            </button>
          )}
        </div>
      </div>

      <div className="password-display">
        {password && strengthResult && (
          <div className="password-strength-section">
            <div className="strength-header">
              <span className="strength-label">
                Password Strength: <strong style={{ color: getStrengthColor(strengthResult.score, 'color') }}>
                  {getStrengthLabel(strengthResult.score)}
                </strong>
              </span>
              <span className="strength-score">
                {strengthResult.score}%
              </span>
            </div>
            <div className="strength-bar-container">
              <div 
                className="strength-bar"
                style={{ 
                  width: `${strengthResult.score}%`,
                  backgroundColor: getStrengthColor(strengthResult.score, 'color')
                }}
              />
            </div>
            {strengthResult.suggestions.length > 0 && (
              <div className="strength-suggestion">
                💡 {strengthResult.suggestions[0]}
              </div>
            )}
          </div>
        )}

      </div>

      <div className="generator-options">
        <div className="option-row">
          <label htmlFor="length">Length: {options.length}</label>
          <input
            type="range"
            id="length"
            min="4"
            max="64"
            value={options.length}
            onChange={(e) => setOptions({ ...options, length: parseInt(e.target.value) })}
            disabled={disabled}
            title={disabled ? "Please complete Service and Username first" : ""}
            className="length-slider"
          />
        </div>

        <div className="checkbox-grid">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={options.includeUppercase}
              onChange={(e) => setOptions({ ...options, includeUppercase: e.target.checked })}
              disabled={disabled}
              title={disabled ? "Please complete Service and Username first" : ""}
            />
            <span>Uppercase (A-Z)</span>
          </label>
          
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={options.includeLowercase}
              onChange={(e) => setOptions({ ...options, includeLowercase: e.target.checked })}
              disabled={disabled}
              title={disabled ? "Please complete Service and Username first" : ""}
            />
            <span>Lowercase (a-z)</span>
          </label>
          
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={options.includeNumbers}
              onChange={(e) => setOptions({ ...options, includeNumbers: e.target.checked })}
              disabled={disabled}
              title={disabled ? "Please complete Service and Username first" : ""}
            />
            <span>Numbers (0-9)</span>
          </label>
          
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={options.includeSymbols}
              onChange={(e) => setOptions({ ...options, includeSymbols: e.target.checked })}
              disabled={disabled}
              title={disabled ? "Please complete Service and Username first" : ""}
            />
            <span>Symbols (!@#$...)</span>
          </label>
          
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={options.excludeSimilar}
              onChange={(e) => setOptions({ ...options, excludeSimilar: e.target.checked })}
              disabled={disabled}
              title={disabled ? "Please complete Service and Username first" : ""}
            />
            <span>Avoid confusing characters (i,l,1,L,o,0,O)</span>
          </label>
        </div>
      </div>

      <div className="generator-actions" style={{ marginTop: '20px', display: 'flex', gap: '12px', justifyContent: 'center', maxWidth: '400px', marginLeft: 'auto', marginRight: 'auto' }}>
        <button
          type="button"
          onClick={handleGenerate}
          disabled={disabled}
          title={disabled ? "Please complete Service and Username first" : "Generate new password"}
          className="btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
          style={{ flex: 1 }}
        >
          Generate New
        </button>
        
        {password.length > 0 && (
          <button
            type="button"
            onClick={handleClear}
            disabled={disabled}
            className="btn btn-danger"
            style={{ flex: 1 }}
            title="Clear password"
          >
            Clear
          </button>
        )}
      </div>
    </div>
  );
}

export default PasswordGenerator;