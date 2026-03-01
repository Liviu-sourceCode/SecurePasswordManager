// Centralized Tauri environment detection used across the app
// Returns true when running inside a Tauri desktop webview
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';

export function isTauriEnv(): boolean {
  const w = window as any;
  try {
    // Tauri exposes globals when running inside its webview (v2 keeps internals private but still sets markers)
    const globalsPresent = Boolean(w.__TAURI__ || w.__TAURI_INTERNALS__ || w.__TAURI_METADATA__);
    // Attempt to obtain the current webview window; this will throw or be undefined outside Tauri
    let windowReady = false;
    try {
      const win = typeof getCurrentWebviewWindow === 'function' ? getCurrentWebviewWindow() : undefined;
      windowReady = !!win && typeof (win as any).label === 'string';
    } catch {
      windowReady = false;
    }
    // In some builds, userAgent contains 'Tauri'
    const uaHintsPresent = typeof navigator !== 'undefined' && /Tauri/i.test(navigator.userAgent || '');
    return globalsPresent || windowReady || uaHintsPresent;
  } catch {
    return false;
  }
}