import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { isTauriEnv } from '../utils/tauriEnv';
import { PasswordEntry } from '../types';

interface UnlockFormProps {
  onUnlock: (entries: PasswordEntry[]) => void;
}

export function UnlockForm({ onUnlock }: UnlockFormProps) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [needsTotp, setNeedsTotp] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [verifyingTotp, setVerifyingTotp] = useState(false);

  const handleTotpChange = (value: string) => {
    const digits = value.replace(/\D/g, '');
    const truncated = digits.substring(0, 6);
    if (truncated.length > 3) {
      setTotpCode(truncated.slice(0, 3) + ' ' + truncated.slice(3));
    } else {
      setTotpCode(truncated);
    }
  };

  const handlePasswordChange = (value: string) => {
    setPassword(value);
    setError(''); // Clear unlock errors when typing

  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (needsTotp) {
      await handleVerifyTotp();
      return;
    }

    try {
      // Check if Tauri API is available
      if (!isTauriEnv()) {
        setError('Tauri APIs are unavailable in browser preview. Please run "npm run tauri dev".');
        return;
      }
      setIsUnlocking(true);
      console.log('Attempting to unlock vault with password...');
      const entries = await invoke<PasswordEntry[]>('unlock_vault', { password });
      console.log('Vault unlocked successfully without 2FA, entries count:', entries.length);
      onUnlock(entries);
      // Cleanup sensitive state after success
      setPassword('');
      setTotpCode('');
      setNeedsTotp(false);
      setError('');
    } catch (err) {
      console.error('Error during initial unlock attempt:', err);
      const msg = (err instanceof Error ? err.message : String(err));
      const lower = msg.toLowerCase();
      
      // If backend requires TOTP, show TOTP input and guide user to verify
      if (lower.includes('totp required')) {
        console.log('2FA required, showing TOTP input');
        setNeedsTotp(true);
        setError('Two-factor authentication required. Please enter your TOTP code from your authenticator app.');
      } else if (lower.includes('invalid password')) {
        setError('Invalid master password. Please check your password and try again.');
        // Clear password on invalid password for safety
        setPassword('');
      } else {
        setError(`Unlock failed: ${msg}`);
      }
    } finally {
      setIsUnlocking(false);
    }
  };

  // Verify TOTP and then retry unlock
  const handleVerifyTotp = async () => {
    if (!totpCode.trim()) {
      setError('Please enter your TOTP code.');
      return;
    }
    setVerifyingTotp(true);
    setError('');
    try {
      console.log('Verifying TOTP code...');
      const ok = await invoke<boolean>('verify_totp', { code: totpCode.replace(/\s/g, '').trim() });
      console.log('TOTP verification result:', ok);
      
      if (!ok) {
        setError('Invalid TOTP code. Please try again.');
        // Clear TOTP code on failure
        setTotpCode('');
        setVerifyingTotp(false);
        return;
      }
      
      console.log('TOTP verified successfully, attempting to unlock vault...');
      // Re-attempt unlock after successful verification
      const entries = await invoke<PasswordEntry[]>('unlock_vault', { password });
      console.log('Vault unlocked successfully, entries count:', entries.length);
      onUnlock(entries);
      // Cleanup sensitive state after success
      setPassword('');
      setTotpCode('');
      setNeedsTotp(false);
      setError('');
    } catch (err) {
      console.error('Error during TOTP verification or unlock:', err);
      const msg = err instanceof Error ? err.message : String(err);
      const lower = msg.toLowerCase();
      
      // Provide more specific error messages
      if (lower.includes('totp required')) {
        setError('2FA verification failed. Please try again.');
      } else if (lower.includes('invalid password')) {
        setError('Invalid master password. Please check your password.');
      } else if (lower.includes('invalid totp')) {
        setError('Invalid TOTP code. Please check your authenticator app.');
      } else {
        setError(`Unlock failed: ${msg}`);
      }
      setVerifyingTotp(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="card p-8 max-w-md w-full mx-auto">
        <h1 className="text-2xl font-bold mb-4 center">Password Manager</h1>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="form-row">
            <label htmlFor="password" className="password-form-label">
              Master Password
            </label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => handlePasswordChange(e.target.value)}
              required
              className="w-full px-6 py-3 border rounded-xl focus:outline-none focus:ring-2 transition-all duration-200 border-gray-600 bg-gray-800/50 text-white focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          {needsTotp && (
            <div className="form-row">
              <label htmlFor="totp" className="password-form-label">
                Two-Factor Code
              </label>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9\s]*"
                id="totp"
                value={totpCode}
                onChange={(e) => handleTotpChange(e.target.value)}
                placeholder="Enter 6-digit code"
                maxLength={7}
                className="w-full px-6 py-3 border rounded-xl focus:outline-none focus:ring-2 transition-all duration-200 border-gray-600 bg-gray-800/50 text-white focus:ring-blue-500 focus:border-blue-500 text-center tracking-widest"
              />
            </div>
          )}

          {error && <p className="text-red-500 text-sm center">{error}</p>}
          <div className="controls flex justify-center">
            <button
              type="submit"
              className="btn btn-primary px-8 py-3"
              disabled={verifyingTotp || isUnlocking}
            >
              {needsTotp
                ? (verifyingTotp ? 'Verifying...' : 'Verify & Unlock')
                : (isUnlocking ? 'Unlocking...' : 'Unlock Vault')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
