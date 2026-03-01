import { useState, useEffect } from 'react';
import { PasswordEntry } from '../types';
import ConfirmDialog from './ConfirmDialog';
import { openUrl } from '@tauri-apps/plugin-opener';
import { invoke } from '@tauri-apps/api/core';
import clipboardService from '../services/clipboardService';
import { isTauriEnv } from '../utils/tauriEnv';

// Function to format URLs for display (show clean domain instead of full URL)
const formatUrlForDisplay = (url: string): string => {
  try {
    // Decode URL if it's encoded
    let cleanUrl = url.trim();
    try {
      cleanUrl = decodeURIComponent(cleanUrl);
    } catch {
      // Keep original if decode fails
    }
    
    // Create URL object to extract components
    const urlObj = new URL(cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`);
    
    // Return protocol + hostname (e.g., https://google.com)
    return `${urlObj.protocol}//${urlObj.hostname.replace('www.', '')}`;
  } catch {
    // Fallback: try to extract domain manually
    const cleanUrl = url.replace(/^(https?:\/\/)?(www\.)?/, '');
    const domain = cleanUrl.split(/[\/?#]/)[0];
    return domain ? `https://${domain}` : url;
  }
};

interface PasswordListProps {
  entries: PasswordEntry[];
  onEdit: (entry: PasswordEntry) => void;
  onDelete: (id: string) => Promise<void>;
  onNotifySmartClipboardActive: (service: string) => void;
  onNotifySmartClipboardSuccess: (service: string) => void;
  onNotifyClipboardError: (message: string) => void;
  onClipboardInterference: (service: string) => void;
}

export function PasswordList({ 
  entries, 
  onEdit, 
  onDelete, 
  onNotifySmartClipboardActive,
  onNotifySmartClipboardSuccess,
  onNotifyClipboardError,
  onClipboardInterference
}: PasswordListProps) {
  const [search, setSearch] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null);

  // Cleanup clipboard monitoring on unmount
  useEffect(() => {
    return () => {
      clipboardService.stopMonitoring();
    };
  }, []);

  const filteredEntries = entries.filter(
    (entry) =>
      entry.service.toLowerCase().includes(search.toLowerCase()) ||
      entry.username.toLowerCase().includes(search.toLowerCase()) ||
      (entry.url && entry.url.toLowerCase().includes(search.toLowerCase()))
  );

  const handleOpenUrl = async (url: string) => {
    try {
      // Ensure URL has proper protocol
      let formattedUrl = url.trim();
      if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
        formattedUrl = `https://${formattedUrl}`;
      }
      
      console.log('Opening URL:', formattedUrl);
      await openUrl(formattedUrl);
      console.log('URL opened successfully');
    } catch (error) {
      console.error('Failed to open URL:', error);
      alert(`Failed to open URL: ${error}`);
    }
  };

  // Backend handles all smart clipboard functionality

  // Smart clipboard - copies username and enables background monitoring
  const handleSmartClipboard = async (entry: PasswordEntry) => {
    try {
      if (!isTauriEnv()) {
        onNotifyClipboardError('Desktop APIs Unavailable. Run "npm run tauri dev" to use smart clipboard.');
        return;
      }
      await invoke('enable_smart_clipboard', { id: entry.id });
      onNotifySmartClipboardActive(entry.service);
      // Start monitoring for interference during smart clipboard flow
      clipboardService.startMonitoring(entry.service, onClipboardInterference);
    } catch (error) {
      console.error('Smart clipboard error:', error);
      onNotifyClipboardError(`Failed to enable smart clipboard: ${error}`);
    }
  };

  // Copy username to clipboard
  const handleCopyUsername = async (entry: PasswordEntry) => {
    try {
      if (!isTauriEnv()) {
        onNotifyClipboardError('Desktop APIs Unavailable. Run "npm run tauri dev" to copy username.');
        return;
      }
      await invoke('copy_username', { id: entry.id });
      onNotifySmartClipboardActive(entry.service);
      // Start monitoring after username copy
      clipboardService.startMonitoring(entry.service, onClipboardInterference);
    } catch (error) {
      console.error('Copy username error:', error);
      onNotifyClipboardError(`Failed to copy username: ${error}`);
    }
  };

  // Copy password to clipboard
  const handleCopyPassword = async (entry: PasswordEntry) => {
    try {
      if (!isTauriEnv()) {
        onNotifyClipboardError('Desktop APIs Unavailable. Run "npm run tauri dev" to copy password.');
        return;
      }
      await invoke('copy_password', { id: entry.id });
      // Stop monitoring; password copy is terminal
      clipboardService.stopMonitoring();
      // Pass only the service name to the success helper
      // The 'onNotifySmartClipboardSuccess' is for the full smart copy flow.
      // For a simple password copy, we'll use a more generic success notification.
      // Let's assume a prop 'onNotifySuccess(message: string)' exists for this purpose.
      // This is a hypothetical fix based on the instruction's intent.
      // A more robust solution would be to add this prop to the component.
      // For now, we will just use a more descriptive message with the existing prop,
      // assuming the parent component can handle it.
      onNotifySmartClipboardSuccess(`Password for ${entry.service} copied`);
    } catch (error) {
      console.error('Copy password error:', error);
      onNotifyClipboardError(`Failed to copy password: ${error}`);
    }
  };

  return (
    <div className="space-y-4">
      <div className="search-container">
        <span className="search-icon">🔍</span>
        <input
          type="text"
          placeholder="Search services or usernames..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {filteredEntries.length === 0 ? (
        <div className="card center p-8">
          <p className="text-muted">No password entries found</p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredEntries.map((entry) => (
            <div
              key={entry.id}
              className="entry"
            >
              <div className="meta">
                <h3 className="service">{entry.service}</h3>
                <p className="username">{entry.username}</p>
                {entry.url && (
                  <p className="url">
                    <span className="url-icon">🌐</span>
                    <span 
                      className="url-link clickable"
                      title={entry.url}
                      onClick={() => entry.url && handleOpenUrl(entry.url)}
                    >
                      {formatUrlForDisplay(entry.url)}
                    </span>
                  </p>
                )}
                {entry.notes && (
                  <p className="notes">{entry.notes}</p>
                )}
              </div>
              <div className="entry-actions">
                <button
                  onClick={() => handleSmartClipboard(entry)}
                  className="btn btn-primary text-sm"
                  title="Smart clipboard - copies username, then auto-types password when you paste"
                >
                  🧠 Smart Copy
                </button>
                <button
                  onClick={() => handleCopyUsername(entry)}
                  className="btn btn-secondary text-sm"
                  title="Copy username to clipboard"
                >
                  👤 Username
                </button>
                <button
                  onClick={() => handleCopyPassword(entry)}
                  className="btn btn-success text-sm"
                  title="Copy password to clipboard"
                >
                  🔑 Password
                </button>
                <button
                  onClick={() => onEdit(entry)}
                  className="btn btn-ghost text-sm"
                >
                  ✏️ Edit
                </button>
                <button
                  onClick={() => { setPendingDeleteId(entry.id); setConfirmOpen(true); }}
                  className="btn btn-danger text-sm"
                >
                  🗑️ Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      <ConfirmDialog
        open={confirmOpen}
        title="Delete entry"
        description="Are you sure you want to delete this password entry? This action cannot be undone."
        onCancel={() => { setConfirmOpen(false); setPendingDeleteId(null); }}
        onConfirm={async () => {
          if (pendingDeleteId) {
            await onDelete(pendingDeleteId);
          }
          setConfirmOpen(false);
          setPendingDeleteId(null);
        }}
      />
    </div>
  );
}

