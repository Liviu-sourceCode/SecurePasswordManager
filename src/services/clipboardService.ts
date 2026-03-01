import { invoke } from '@tauri-apps/api/core';
import { isTauriEnv } from '../utils/tauriEnv';

class ClipboardService {
  private interferenceCheckInterval: any = null;
  private onInterferenceDetected: ((service: string) => void) | null = null;
  private currentService: string = '';
  private isMonitoring: boolean = false;

  /**
   * Start monitoring clipboard for interference
   * @param service - The service name for which smart clipboard is active
   * @param onInterference - Callback function to call when interference is detected
   */
  startMonitoring(service: string, onInterference: (service: string) => void) {
    // Bail out safely if not in Tauri desktop environment
    if (!isTauriEnv()) {
      console.warn('[ClipboardService] Desktop APIs unavailable; monitoring not started.');
      return;
    }
    this.currentService = service;
    this.onInterferenceDetected = onInterference;
    this.isMonitoring = true;

    // Check for interference every 2 seconds
    this.interferenceCheckInterval = setInterval(async () => {
      if (!this.isMonitoring) {
        return;
      }

      try {
        const interferenceDetected = await invoke<boolean>('check_clipboard_interference');
        
        if (interferenceDetected && this.onInterferenceDetected) {
          console.log('[ClipboardService] Interference detected for service:', this.currentService);
          this.onInterferenceDetected(this.currentService);
        }
      } catch (error) {
        console.error('[ClipboardService] Error checking clipboard interference:', error);
      }
    }, 2000);

    console.log('[ClipboardService] Started monitoring clipboard for service:', service);
  }

  /**
   * Stop monitoring clipboard interference
   */
  stopMonitoring() {
    if (this.interferenceCheckInterval) {
      clearInterval(this.interferenceCheckInterval);
      this.interferenceCheckInterval = null;
    }
    
    this.isMonitoring = false;
    this.onInterferenceDetected = null;
    this.currentService = '';
    
    console.log('[ClipboardService] Stopped monitoring clipboard');
  }

  /**
   * Check if currently monitoring
   */
  isCurrentlyMonitoring(): boolean {
    return this.isMonitoring;
  }

  /**
   * Get the current service being monitored
   */
  getCurrentService(): string {
    return this.currentService;
  }
}
export const clipboardService = new ClipboardService();
export default clipboardService;