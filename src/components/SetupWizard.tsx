import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { PasswordEntry } from '../types';
import { analyzePasswordStrength, getStrengthColor, getStrengthLabel, PasswordStrengthResult } from '../utils/passwordStrength';
import { isTauriEnv } from '../utils/tauriEnv';

interface SetupWizardProps {
  onComplete: (entries: PasswordEntry[]) => void;
}

export function SetupWizard({ onComplete }: SetupWizardProps) {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [strengthResult, setStrengthResult] = useState<PasswordStrengthResult | null>(null);
  const [error, setError] = useState('');
  const [isCreating, setIsCreating] = useState(false);

  useEffect(() => {
    if (password) {
      setStrengthResult(analyzePasswordStrength(password));
    } else {
      setStrengthResult(null);
    }
  }, [password]);

  const handlePasswordChange = (value: string) => {
    setPassword(value);
    setError('');
  };

  const canProceed = () => {
    return strengthResult && strengthResult.score >= 60 && password === confirmPassword;
  };

  const handleNext = async () => {
    if (canProceed()) {
      setIsCreating(true);
      setError('');
      try {
        // Guard desktop APIs when in browser preview
        if (isTauriEnv()) {
          const entries = await invoke<PasswordEntry[]>('create_vault', { password });
          onComplete(entries);
        } else {
          console.log('Simulating vault creation in browser for UI testing.');
          // In a browser environment, we can simulate success for UI testing
          // by passing empty entries to the onComplete handler.
          onComplete([]);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsCreating(false);
      }
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="card p-8 max-w-md w-full mx-auto">
        <h1 className="text-2xl font-bold mb-4 center">Create Your Vault</h1>
        <div className="space-y-4">
          <div className="form-row">
            <label htmlFor="password" className="password-form-label">
              Master Password
            </label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => handlePasswordChange(e.target.value)}
              placeholder="Enter a strong password"
              required
              className="w-full px-6 py-3 border rounded-xl focus:outline-none focus:ring-2 transition-all duration-200 border-gray-600 bg-gray-800/50 text-white focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          {/* Password Strength */}
          {password && strengthResult && (
            <div className="space-y-2">
              <div className="flex justify-between items-center text-sm">
                <span>Password Strength</span>
                <span style={{ color: getStrengthColor(strengthResult.score, 'color') }}>
                  {getStrengthLabel(strengthResult.score)} ({strengthResult.score}%)
                </span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div 
                  className="h-full rounded-full transition-all duration-300"
                  style={{ 
                    width: `${strengthResult.score}%`,
                    backgroundColor: getStrengthColor(strengthResult.score, 'color')
                  }}
                />
              </div>
              {strengthResult.suggestions.length > 0 && strengthResult.score < 80 && (
                <p className="text-xs text-gray-400">
                  💡 {strengthResult.suggestions[0]}
                </p>
              )}
            </div>
          )}

          {/* Confirm Password */}
          {password && strengthResult && strengthResult.score >= 60 && (
            <div className="form-row">
              <label htmlFor="confirmPassword" className="password-form-label">
                Confirm Password
              </label>
              <input
                type="password"
                id="confirmPassword"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Re-enter your password"
                className={`w-full px-6 py-3 border rounded-xl focus:outline-none focus:ring-2 transition-all duration-200 ${
                  confirmPassword && password !== confirmPassword 
                    ? 'border-red-500 bg-gray-800/50 text-white focus:ring-red-500 focus:border-red-500' 
                    : 'border-gray-600 bg-gray-800/50 text-white focus:ring-blue-500 focus:border-blue-500'
                }`}
              />
              {confirmPassword && password !== confirmPassword && (
                <p className="text-red-500 text-sm">Passwords do not match</p>
              )}
            </div>
          )}

          {error && <p className="text-red-500 text-sm center">{error}</p>}
          
          <div className="controls">
            <button
              onClick={handleNext}
              disabled={!canProceed() || isCreating}
              className="btn btn-primary w-full"
            >
              {isCreating ? 'Creating Vault...' : 'Create Vault'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}