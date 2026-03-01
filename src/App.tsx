import React, { useState, useEffect, useCallback } from 'react';
import { ask, open } from '@tauri-apps/plugin-dialog';
import { invoke } from '@tauri-apps/api/core';
import { register, unregister } from '@tauri-apps/plugin-global-shortcut';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';
import { isTauriEnv } from './utils/tauriEnv';
import { UnlockForm } from './components/UnlockForm';
import { SetupWizard } from './components/SetupWizard';
import { PasswordList } from './components/PasswordList';
import { PasswordForm } from './components/PasswordForm';
import SecurityAnalysis from './components/SecurityAnalysis';
import { NotificationSystem, useNotifications } from './components/NotificationSystem';
import clipboardService from './services/clipboardService';
import TOTPSetup from './components/TOTPSetup';

import { PasswordEntry } from './types';
import './App.css';
import { join } from '@tauri-apps/api/path';
import { listen } from '@tauri-apps/api/event';

// TypeScript declaration for Tauri global
declare global {
  interface Window {
    __TAURI__?: any;
  }
}

export default function App() {
  const [isLocked, setIsLocked] = useState(true);
  const [entries, setEntries] = useState<PasswordEntry[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [editEntry, setEditEntry] = useState<PasswordEntry | undefined>();
  const [vaultExists, setVaultExists] = useState<boolean | null>(null); // null = checking, true/false = result
  const [showTotpSetup, setShowTotpSetup] = useState(false);
  const [totpEnabled, setTotpEnabled] = useState(false);
  const {
    notifications,
    addNotification,
    removeNotification,
    notifySmartClipboardActive,
    notifySmartClipboardSuccess,
  } = useNotifications();

  const handleClipboardInterference = (service: string) => {
    addNotification({
      type: 'warning',
      title: '⚠️ Clipboard Interference',
      message: `Clipboard interference detected and resolved for ${service}. Your credentials remain secure.`,
      duration: 6000
    });
  };

  // Set up clipboard interference monitoring
  React.useEffect(() => {
    // This will be called when smart clipboard is enabled
    // The actual monitoring start will be triggered from PasswordList component
    return () => {
      clipboardService.stopMonitoring();
    };
  }, []);

  // Listen for backend auto-lock events and immediately reflect lock state in the UI
  useEffect(() => {
    if (!isTauriEnv()) return;
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        unlisten = await listen('vault_auto_locked', (event: any) => {
          const reason = typeof event?.payload?.reason === 'string' ? event.payload.reason : 'timeout';
          addNotification({
            type: 'warning',
            title: '🔒 Vault Auto-Locked',
            message: reason === 'inactivity' ? 'Vault was locked due to inactivity.' : 'Vault session expired and was locked.',
            duration: 6000,
          });
          // Reflect locked state in UI and stop any ongoing clipboard monitoring
          setIsLocked(true);
          setEntries([]);
          setShowForm(false);
          setEditEntry(undefined);
          clipboardService.stopMonitoring();
        });
      } catch (e) {
        console.warn('Failed to subscribe to vault_auto_locked event:', e);
      }
    })();
    return () => {
      try { unlisten?.(); } catch {}
    };
  }, []);
  const checkVaultExists = useCallback(async () => {
    const waitForTauriReady = async (maxRetries = 10, retryDelay = 300) => {
      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        if (isTauriEnv()) return true;
        await new Promise((resolve) => setTimeout(resolve, retryDelay));
      }
      return false;
    };

    const ready = await waitForTauriReady();
    if (!ready) {
      console.warn('Tauri not available after waiting');
      setVaultExists(false);
      return;
    }

    try {
      const exists = await invoke<boolean>('vault_exists');
      console.log('DEBUG: vault_exists returned', exists);
      setVaultExists(exists);
    } catch (error) {
      console.error('Error checking vault existence:', error);
      setVaultExists(false);
    }
  }, []);

  useEffect(() => {
    // Register global shortcut using Tauri v2 plugin (only in Tauri environment)
    const registerShortcuts = async () => {
      try {
        if (isTauriEnv()) {
          await register('CommandOrControl+Shift+P', async () => {
            const win = getCurrentWebviewWindow();
            await win.show();
            await win.setFocus();
          });
        }
      } catch (err) {
        console.warn('Global shortcuts not available:', err instanceof Error ? err.message : String(err));
      }
    };

    console.log('DEBUG: App useEffect triggered, calling checkVaultExists');
    checkVaultExists();
    registerShortcuts();

    return () => {
      try {
        if (isTauriEnv()) {
          unregister('CommandOrControl+Shift+P').catch(() => {});
        }
      } catch (e) {
        // Ignore cleanup errors
      }
    };
  }, [checkVaultExists]);

  useEffect(() => {
    const handlePaste = async () => {
      if (clipboardService.isCurrentlyMonitoring()) {
        try {
          await invoke('trigger_password_autotype');
          notifySmartClipboardSuccess(clipboardService.getCurrentService());
          clipboardService.stopMonitoring();
        } catch (error) {
          console.error('Failed to trigger password autotype:', error);
        }
      }
    };

    window.addEventListener('paste', handlePaste);

    return () => {
      window.removeEventListener('paste', handlePaste);
    };
  }, [notifySmartClipboardSuccess]);

  // Ensure hooks order is consistent across renders: place this before any conditional returns
  useEffect(() => {
    if (!isLocked && isTauriEnv()) {
      invoke<boolean>('totp_account_status')
        .then((enabled) => setTotpEnabled(enabled))
        .catch(() => setTotpEnabled(false));
    }
  }, [isLocked]);

  const handleUnlock = (newEntries: PasswordEntry[]) => {
    setEntries(newEntries);
    setIsLocked(false);
    setVaultExists(true); // Vault now exists after successful unlock
  };

  const handleSetupComplete = (newEntries: PasswordEntry[]) => {
    setEntries(newEntries);
    setIsLocked(false);
    setVaultExists(true);
  };



  const handleAdd = () => {
    setEditEntry(undefined);
    setShowForm(true);
  };

  const handleLock = async () => {
    try {
      // Check if Tauri API is available
      if (!isTauriEnv()) {
        console.error('Tauri API not available - cannot lock vault');
        addNotification({
          type: 'error',
          title: 'Desktop APIs Unavailable',
          message: 'Run the desktop app via "npm run tauri dev" to lock the vault.',
          duration: 5000,
        });
        return;
      }
      await invoke('lock_vault');
      setIsLocked(true);
      setEntries([]);
    } catch (err) {
      console.error('Failed to lock vault:', err);
      addNotification({
        type: 'error',
        title: '❌ Lock Failed',
        message: err instanceof Error ? err.message : 'Failed to lock vault',
        duration: 5000,
      });
    }
  };

  const handleDeleteVault = async () => {
    const confirmed = await ask('Are you sure you want to delete the entire vault? This action cannot be undone!', {
      title: 'Delete Vault',
    });

    if (confirmed) {
      try {
        if (!isTauriEnv()) {
          addNotification({
            type: 'error',
            title: 'Desktop APIs Unavailable',
            message: 'Run the desktop app via "npm run tauri dev" to delete the vault.',
            duration: 5000,
          });
          return;
        }
        await invoke('delete_vault');
        setIsLocked(true);
        setEntries([]);
        setVaultExists(false);
        addNotification({
          type: 'success',
          title: '✅ Vault Deleted',
          message: 'Vault has been successfully deleted. You can now test the setup process.',
          duration: 5000
        });
      } catch (err) {
        addNotification({
          type: 'error',
          title: '❌ Delete Failed',
          message: err instanceof Error ? err.message : String(err),
          duration: 5000
        });
      }
    }
  };

  const handleExportVault = async () => {
    try {
      if (!isTauriEnv()) {
        addNotification({
          type: 'error',
          title: 'Desktop APIs Unavailable',
          message: 'Run the desktop app via "npm run tauri dev" to export the vault.',
          duration: 5000,
        });
        return;
      }
      const selected = await open({
        multiple: false,
        directory: true,
        title: 'Select Export Folder',
      });
      if (!selected || (Array.isArray(selected) && selected.length === 0)) return; // user cancelled
      const dirPath = Array.isArray(selected) ? selected[0] : selected;
      const destPath = await join(dirPath, 'vault.enc');
      console.debug('Exporting vault to:', destPath);
      const exportArgs = { destPath };
      console.debug('export_vault_file args:', exportArgs);
      try {
        await invoke('export_vault_file', exportArgs);
        await invoke<void>('export_vault_file', exportArgs);
      } catch (invokeErr) {
        // Surface the backend error and log details to the console for debugging
        const errMsg = invokeErr instanceof Error ? invokeErr.message : String(invokeErr);
        console.error('Export failed:', { destPath, error: errMsg });
        throw new Error(errMsg || 'Failed to export vault file');
      }

      addNotification({
        type: 'success',
        title: '✅ Vault Exported',
        message: 'Vault file exported successfully.',
        duration: 5000,
      });
    } catch (err) {
      addNotification({
        type: 'error',
        title: '❌ Export Failed',
        message: err instanceof Error ? err.message : 'Failed to export vault file',
        duration: 6000,
      });
    }
  };

  const handleImportVault = async () => {
    try {
      if (!isTauriEnv()) {
        addNotification({
          type: 'error',
          title: 'Desktop APIs Unavailable',
          message: 'Run the desktop app via "npm run tauri dev" to import a vault file.',
          duration: 5000,
        });
        return;
      }
      const srcPath = await open({
        multiple: false,
        directory: false,
        title: 'Import Vault File',
        filters: [{ name: 'Vault', extensions: ['enc', 'json'] }],
      });
      if (!srcPath || (Array.isArray(srcPath) && srcPath.length === 0)) return; // cancelled
      const filePath = Array.isArray(srcPath) ? srcPath[0] : srcPath;

      const confirmed = await ask('Importing will replace the current vault with the selected file and lock the session. Continue?', { title: 'Confirm Import' });
      if (!confirmed) return;

      const importArgs = { srcPath: filePath };
      console.debug('import_vault_file args:', importArgs);
      await invoke('import_vault_file', importArgs);

      // Reset UI state to reflect locked vault after import
      setIsLocked(true);
      setEntries([]);
      setVaultExists(true);

      addNotification({
        type: 'success',
        title: '✅ Vault Imported',
        message: 'Vault file imported successfully. Please unlock to continue.',
        duration: 6000,
      });
    } catch (err) {
      addNotification({
        type: 'error',
        title: '❌ Import Failed',
        message: err instanceof Error ? err.message : 'Failed to import vault file',
        duration: 6000,
      });
    }
  };

  const handleEdit = (entry: PasswordEntry) => {
    setEditEntry(entry);
    setShowForm(true);
  };

  const handleDelete = async (id: string) => {
    try {
      if (!isTauriEnv()) {
        console.error('Tauri API not available - cannot delete entry');
        addNotification({
          type: 'error',
          title: 'Desktop APIs Unavailable',
          message: 'Run the desktop app via "npm run tauri dev" to delete entries.',
          duration: 5000,
        });
        return;
      }
      const updatedEntries = await invoke<PasswordEntry[]>('delete_entry', { id });
      setEntries(updatedEntries);
    } catch (err) {
      console.error('Failed to delete entry:', err);
      addNotification({
        type: 'error',
        title: '❌ Delete Failed',
        message: err instanceof Error ? err.message : 'Failed to delete password entry',
        duration: 5000
      });
    }
  };

  const handleSave = async (entry: Omit<PasswordEntry, 'id' | 'created_at' | 'updated_at'>) => {
    try {
      if (!isTauriEnv()) {
        console.error('Tauri API not available - cannot save entry');
        addNotification({
          type: 'error',
          title: 'Desktop APIs Unavailable',
          message: 'Run the desktop app via "npm run tauri dev" to add or update entries.',
          duration: 5000,
        });
        return;
      }
      if (editEntry) {
        const updatedEntry = {
          ...entry,
          id: editEntry.id,
          created_at: editEntry.created_at,
          updated_at: new Date().toISOString(),
        };
        const updatedEntries = await invoke<PasswordEntry[]>('update_entry', {
          entry: updatedEntry,
        });
        setEntries(updatedEntries);
      } else {
        const updatedEntries = await invoke<PasswordEntry[]>('add_entry', {
          entryData: entry,
        });
        setEntries(updatedEntries);
      }
      setShowForm(false);
      setEditEntry(undefined);
    } catch (err) {
      console.error('Failed to save entry:', err);
      const msg = err instanceof Error ? err.message : String(err);
      // If the vault was auto-locked, reflect that state in the UI immediately
      if (/locked/i.test(msg)) {
        setIsLocked(true);
        setShowForm(false);
        setEditEntry(undefined);
      }
      addNotification({
        type: 'error',
        title: '❌ Save Failed',
        message: msg || 'Failed to save password entry',
        duration: 5000
      });
    }
  };

  // Show loading state while checking vault existence
  if (vaultExists === null) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Checking vault status...</p>
        </div>
      </div>
    );
  }

  console.log('DEBUG: Current state - vaultExists:', vaultExists, 'isLocked:', isLocked);

  // No vault exists → SetupWizard (better UX for first-time users)
  if (vaultExists === false && isLocked) {
    return (
      <div>
        <SetupWizard onComplete={handleSetupComplete} />
      </div>
    );
  }

  // Existing vault → UnlockForm (require master password to unlock)
  if (vaultExists === true && isLocked) {
    return (
      <div>
        <UnlockForm onUnlock={handleUnlock} />
      </div>
    );
  }

  // vault_auto_locked listener moved above conditional returns to maintain stable hook order

  return (
    <div className="app">
      <div className="container">
        <div className="header">
          <h1>Password Manager</h1>
          <div className="flex items-center space-x-4">
            <button
              onClick={handleExportVault}
              className="btn btn-ghost"
              title="Export vault to file"
            >
              ⬇️ Export Vault
            </button>
            <button
              onClick={handleImportVault}
              className="btn btn-ghost"
              title="Import vault from file"
            >
              ⬆️ Import Vault
            </button>
            <button
              onClick={handleDeleteVault}
              className="btn btn-ghost text-red-600 hover:bg-red-50"
              title="Delete vault for testing"
            >
              🗑️ Delete Vault
            </button>
            <button
              onClick={handleLock}
              className="btn btn-ghost"
            >
              Lock
            </button>
            {!isLocked && !totpEnabled && (
              <button className="btn btn-secondary" onClick={() => setShowTotpSetup(true)}>
                Enable 2FA
              </button>
            )}
            <button
              onClick={handleAdd}
              className="btn btn-primary"
            >
              Add Password
            </button>
          </div>
        </div>

        {showForm ? (
          <div className="modal-overlay">
            <div className="modal-content">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-bold center">
                  {editEntry ? 'Edit Password' : 'Add Password'}
                </h2>
                <button
                  onClick={() => {
                    setShowForm(false);
                    setEditEntry(undefined);
                  }}
                  className="close-btn"
                  aria-label="Close"
                >
                  ×
                </button>
              </div>
              <PasswordForm
                entry={editEntry}
                onSave={handleSave}
                onCancel={() => {
                  setShowForm(false);
                  setEditEntry(undefined);
                }}
              />
            </div>
          </div>
        ) : (
          <>
            <SecurityAnalysis entries={entries} />
            <PasswordList
              entries={entries}
              onEdit={handleEdit}
              onDelete={handleDelete}
              onNotifySmartClipboardActive={notifySmartClipboardActive}
              onNotifySmartClipboardSuccess={notifySmartClipboardSuccess}
              onNotifyClipboardError={(error) =>
                addNotification({
                  type: 'error',
                  title: 'Clipboard Error',
                  message: error,
                  duration: 5000
                })
              }
              onClipboardInterference={handleClipboardInterference}
            />


          </>
        )}
      </div>
      
      {/* TOTP Setup Modal */}
      {showTotpSetup && (
        <div className="modal-overlay" onClick={() => setShowTotpSetup(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <TOTPSetup 
              onClose={() => setShowTotpSetup(false)} 
              onEnabled={() => setTotpEnabled(true)}
            />
          </div>
        </div>
      )}
      <NotificationSystem 
        notifications={notifications} 
        onRemove={removeNotification} 
      />
    </div>
  );
}
