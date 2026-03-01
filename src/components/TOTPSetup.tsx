import { useReducer, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { isTauriEnv } from '../utils/tauriEnv';

interface TOTPSetupProps {
  onClose: () => void;
  onEnabled?: () => void;
}

// --- State and Reducer ---
interface TOTPState {
  accountName: string;
  issuer: string;
  provisioningUri: string;
  secret: string;
  error: string;
  status: 'idle' | 'generating' | 'generated' | 'verifying' | 'verified' | 'error';
  totpCode: string;
}

const initialState: TOTPState = {
  accountName: 'user',
  issuer: 'SecurePasswordManager',
  provisioningUri: '',
  secret: '',
  error: '',
  status: 'idle',
  totpCode: '',
};

type Action =
  | { type: 'SET_FIELD'; field: 'accountName' | 'issuer' | 'totpCode'; payload: string }
  | { type: 'GENERATE_START' }
  | { type: 'GENERATE_SUCCESS'; payload: { uri: string; secret: string } }
  | { type: 'GENERATE_FAILURE'; payload: string }
  | { type: 'VERIFY_START' }
  | { type: 'VERIFY_SUCCESS' }
  | { type: 'VERIFY_FAILURE'; payload: string }
  | { type: 'RESET_ERROR' };

function totpReducer(state: TOTPState, action: Action): TOTPState {
  switch (action.type) {
    case 'SET_FIELD':
      return { ...state, [action.field]: action.payload, error: '' };
    case 'GENERATE_START':
      return { ...state, status: 'generating', error: '' };
    case 'GENERATE_SUCCESS':
      return { ...state, status: 'generated', provisioningUri: action.payload.uri, secret: action.payload.secret };
    case 'GENERATE_FAILURE':
      return { ...state, status: 'error', error: action.payload };
    case 'VERIFY_START':
      return { ...state, status: 'verifying', error: '' };
    case 'VERIFY_SUCCESS':
      return { ...state, status: 'verified', error: '', totpCode: '' };
    case 'VERIFY_FAILURE':
      return { ...state, status: 'generated', error: action.payload }; // Go back to 'generated' to allow retry
    case 'RESET_ERROR':
      return { ...state, error: '' };
    default:
      return state;
  }
}

// --- Component ---
const TOTPSetup: React.FC<TOTPSetupProps> = ({ onClose, onEnabled }) => {
  const [state, dispatch] = useReducer(totpReducer, initialState);

  // Keep session alive during 2FA setup to prevent auto-lock
  useEffect(() => {
    if (!isTauriEnv()) return;

    const keepAlive = async () => {
      try {
        await invoke('keep_session_alive');
      } catch (error) {
        console.warn('Failed to keep session alive:', error);
      }
    };

    // Call immediately and then every 2 minutes (120 seconds)
    keepAlive();
    const interval = setInterval(keepAlive, 120000);

    return () => clearInterval(interval);
  }, []);

  const handleGenerate = async () => {
    dispatch({ type: 'GENERATE_START' });
    try {
      if (!isTauriEnv()) {
        throw new Error('Tauri APIs not available in browser preview.');
      }
      await invoke('set_totp_account', {
        accountName: state.accountName.trim() || 'user',
        issuer: state.issuer.trim() || 'SecurePasswordManager',
      });
      const { uri, secret } = await invoke<{ uri: string; secret: string }>('init_totp');
      dispatch({ type: 'GENERATE_SUCCESS', payload: { uri, secret } });
      onEnabled?.();
    } catch (e) {
      dispatch({ type: 'GENERATE_FAILURE', payload: e instanceof Error ? e.message : String(e) });
    }
  };

  // Input sanitization and validation
  const sanitizeInput = (input: string): string => {
    return input
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '') // Remove control characters
      .replace(/[^\w\s.-]/g, '') // Only allow alphanumeric, spaces, dots, hyphens
      .trim();
  };

  const validateTotpCode = (code: string): boolean => {
    // Must be exactly 6 digits
    return /^\d{6}$/.test(code);
  };

  const validateIssuerAndAccount = (value: string): string | undefined => {
    if (value.length > 100) return 'Must not exceed 100 characters';
    if (!/^[a-zA-Z0-9\s.-_]+$/.test(value)) {
      return 'Only letters, numbers, spaces, dots, hyphens, and underscores are allowed';
    }
    return undefined;
  };

  const handleVerify = async () => {
    dispatch({ type: 'VERIFY_START' });
    try {
      if (!isTauriEnv()) {
        throw new Error('Tauri APIs not available in browser preview.');
      }
      const code = state.totpCode.trim();
      if (!validateTotpCode(code)) {
        throw new Error('Enter the 6-digit code from your authenticator.');
      }
      const ok = await invoke<boolean>('verify_totp', { code, secret: state.secret });
      if (!ok) {
        throw new Error('Invalid code. Wait for the next 30s window and try again.');
      }
      await invoke('finalize_totp', { secret: state.secret });
      dispatch({ type: 'VERIFY_SUCCESS' });
    } catch (e) {
      dispatch({ type: 'VERIFY_FAILURE', payload: e instanceof Error ? e.message : String(e) });
    }
  };

  const isGenerating = state.status === 'generating';
  const isVerifying = state.status === 'verifying';
  const isVerified = state.status === 'verified';
  const hasGenerated = state.status === 'generated' || state.status === 'verifying' || state.status === 'verified';

  return (
    <div className="modal-overlay">
      <div className="modal-content relative max-w-lg">
        <button 
          onClick={onClose} 
          className="close-btn absolute top-3 right-3 z-50 hover:bg-gray-700/50 rounded-full p-1 transition-colors duration-200"
          style={{ position: 'absolute', top: '12px', right: '12px', zIndex: 50 }}
          aria-label="Close modal"
        >
          ×
        </button>
        
        <div className="p-6">
          <h2 className="text-2xl font-bold text-center text-white mb-6">Enable Two-Factor Authentication</h2>

          {!hasGenerated ? (
            <>
              <p className="text-sm text-gray-400 text-center mb-6">
                Customize the issuer and account name for your authenticator app.
              </p>
              <div className="space-y-4 mb-6">
                <div className="form-row">
                  <label htmlFor="issuer" className="password-form-label">Issuer</label>
                  <input
                    id="issuer"
                    type="text"
                    value={state.issuer}
                    onChange={(e) => {
                      const sanitized = sanitizeInput(e.target.value);
                      const error = validateIssuerAndAccount(sanitized);
                      if (!error) {
                        dispatch({ type: 'SET_FIELD', field: 'issuer', payload: sanitized });
                      }
                    }}
                    className="input-field-wizard"
                    disabled={isGenerating}
                  />
                </div>
                <div className="form-row">
                  <label htmlFor="accountName" className="password-form-label">Account Name</label>
                  <input
                    id="accountName"
                    type="text"
                    value={state.accountName}
                    onChange={(e) => {
                      const sanitized = sanitizeInput(e.target.value);
                      const error = validateIssuerAndAccount(sanitized);
                      if (!error) {
                        dispatch({ type: 'SET_FIELD', field: 'accountName', payload: sanitized });
                      }
                    }}
                    className="input-field-wizard"
                    disabled={isGenerating}
                  />
                </div>
              </div>
            </>
          ) : null}

          {state.error && (
            <div className="mb-4 p-3 bg-red-900/20 border border-red-500/30 rounded-lg">
              <p className="text-red-300 text-sm">{state.error}</p>
            </div>
          )}

          {isVerified ? (
            <div className="text-center p-6 bg-green-900/50 rounded-lg">
              <p className="text-green-300 font-semibold text-lg">🎉 2FA is enabled and verified! 🎉</p>
              <p className="text-gray-400 text-sm mt-2">You can now close this window.</p>
              <div className="flex justify-center mt-4">
                <button onClick={onClose} className="btn btn-ghost">Close</button>
              </div>
            </div>
          ) : null}

          <div className="controls flex justify-center items-center mb-4">
            {!hasGenerated && (
              <button onClick={handleGenerate} disabled={isGenerating} className="btn btn-primary">
                {isGenerating ? 'Generating...' : 'Generate QR Code'}
              </button>
            )}
          </div>

          {hasGenerated && !isVerified && (
            <div className="mt-4 p-6 border border-gray-700 rounded-xl bg-gray-800/40 space-y-6 text-center shadow-inner totp-modal-content">
              <p className="text-base font-semibold text-white">Scan with your Authenticator App</p>
              
              <div className="flex justify-center">
                <div className="bg-white p-3 rounded-lg inline-block">
                  <img
                    alt="TOTP QR Code"
                    className="rounded-lg"
                    src={`https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(state.provisioningUri)}&size=200x200&q=H`}
                  />
                </div>
              </div>
              
              <div className="text-center">
                <p className="text-xs text-gray-400 mb-2">Or manually enter this code:</p>
                <code className="block font-mono bg-gray-700 p-3 rounded-md text-white text-sm break-all select-all">
                  {state.secret}
                </code>
              </div>

              <div className="form-row mt-6">
                <div className="space-y-3">
                  <div className="text-center">
                    <label htmlFor="totp-code" className="password-form-label block whitespace-nowrap">
                      Enter 6-digit code to verify
                    </label>
                  </div>
                  <input
                    id="totp-code"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    value={state.totpCode}
                    onChange={(e) => dispatch({ type: 'SET_FIELD', field: 'totpCode', payload: e.target.value.replace(/\D/g, '') })}
                    className="w-full max-w-xs mx-auto px-6 py-3 border rounded-xl focus:outline-none focus:ring-2 transition-all duration-200 border-gray-600 bg-gray-800/50 text-white focus:ring-blue-500 focus:border-blue-500 text-center tracking-widest text-lg font-mono"
                    placeholder="Enter the 6-digit code"
                  />
                </div>
              </div>
              
              <div className="flex justify-center mt-4">
                <button onClick={handleVerify} disabled={isVerifying || !/^\d{6}$/.test(state.totpCode)} className="btn btn-primary text-base py-2">
                  {isVerifying ? 'Verifying...' : 'Verify & Finish'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default TOTPSetup;