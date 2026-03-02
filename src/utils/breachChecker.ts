/**
 * Enhanced password breach checking utility with improved caching, error handling, and rate limiting
 */

export interface BreachCheckResult {
  isBreached: boolean;
  breachCount?: number;
  error?: string;
  fromCache: boolean;
  responseTime: number;
}

export interface BreachCheckOptions {
  timeout?: number;
  retries?: number;
  retryDelay?: number;
  useCache?: boolean;
  cacheTTL?: number;
}

interface CacheEntry {
  result: boolean;
  breachCount?: number;
  timestamp: number;
  ttl: number;
}

interface EncryptedCacheEntry {
  encryptedData: string;
  iv: string;
  timestamp: number;
  ttl: number;
}

// Secure cache implementation with encryption
class SecureCache {
  private cache = new Map<string, EncryptedCacheEntry>();
  private encryptionKey: CryptoKey | null = null;

  async initialize(): Promise<void> {
    if (!this.encryptionKey) {
      // Generate a key for cache encryption (derived from a stable source)
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode('breach-cache-key-v1-' + navigator.userAgent.slice(0, 20)),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
      );

      this.encryptionKey = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: new TextEncoder().encode('breach-cache-salt'),
          iterations: 10000,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    }
  }

  async set(key: string, entry: CacheEntry): Promise<void> {
    await this.initialize();
    if (!this.encryptionKey) return;

    try {
      const data = JSON.stringify({
        result: entry.result,
        breachCount: entry.breachCount
      });

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedData = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        this.encryptionKey,
        new TextEncoder().encode(data)
      );

      this.cache.set(key, {
        encryptedData: Array.from(new Uint8Array(encryptedData)).map(b => b.toString(16).padStart(2, '0')).join(''),
        iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
        timestamp: entry.timestamp,
        ttl: entry.ttl
      });
    } catch (error) {
      console.warn('Failed to encrypt cache entry:', error);
    }
  }

  async get(key: string): Promise<CacheEntry | null> {
    await this.initialize();
    if (!this.encryptionKey) return null;

    const encryptedEntry = this.cache.get(key);
    if (!encryptedEntry) return null;

    // Check if expired
    const now = Date.now();
    if (now - encryptedEntry.timestamp > encryptedEntry.ttl) {
      this.cache.delete(key);
      return null;
    }

    try {
      const encryptedData = new Uint8Array(
        encryptedEntry.encryptedData.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
      );
      const iv = new Uint8Array(
        encryptedEntry.iv.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
      );

      const decryptedData = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        this.encryptionKey,
        encryptedData
      );

      const data = JSON.parse(new TextDecoder().decode(decryptedData));
      return {
        result: data.result,
        breachCount: data.breachCount,
        timestamp: encryptedEntry.timestamp,
        ttl: encryptedEntry.ttl
      };
    } catch (error) {
      console.warn('Failed to decrypt cache entry:', error);
      this.cache.delete(key);
      return null;
    }
  }

  delete(key: string): void {
    this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }

  cleanup(): void {
    const now = Date.now();
    const maxCacheSize = 1000;

    // Remove expired entries
    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp > entry.ttl) {
        this.cache.delete(key);
      }
    }

    // If cache is still too large, remove oldest entries
    if (this.cache.size > maxCacheSize) {
      const entries = Array.from(this.cache.entries())
        .sort(([, a], [, b]) => a.timestamp - b.timestamp);
      
      const toRemove = entries.slice(0, this.cache.size - maxCacheSize);
      toRemove.forEach(([key]) => this.cache.delete(key));
    }
  }
}

class EnhancedBreachChecker {
  private cache = new SecureCache();
  private readonly rateLimitDelay = 150; // ms between requests (increased for better compliance)
  private readonly burstLimit = 5; // max requests in burst window
  private readonly burstWindow = 10000; // 10 seconds burst window
  private lastRequestTime = 0;
  private requestTimes: number[] = []; // Track request times for burst limiting
  private consecutiveErrors = 0;
  private backoffMultiplier = 1;

  /**
   * Check if a password has been breached
   */
  async checkPassword(
    password: string, 
    options: BreachCheckOptions = {}
  ): Promise<BreachCheckResult> {
    const startTime = Date.now();
    const {
      timeout = 10000,
      retries = 2,
      retryDelay = 1000,
      useCache = true,
      cacheTTL = 24 * 60 * 60 * 1000 // 24 hours
    } = options;

    try {
      // Generate cache key
      const cacheKey = await this.createCacheKey(password);
      
      // Check cache first
      if (useCache) {
        const cachedResult = await this.cache.get(cacheKey);
        if (cachedResult) {
          return {
            isBreached: cachedResult.result,
            breachCount: cachedResult.breachCount,
            fromCache: true,
            responseTime: Date.now() - startTime
          };
        }
      }

      // Perform breach check with retries
      let lastError: Error | null = null;
      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          const result = await this.performBreachCheck(password, timeout);
          
          // Reset error tracking on success
          this.consecutiveErrors = 0;
          this.backoffMultiplier = Math.max(1, this.backoffMultiplier * 0.9); // Gradually reduce backoff
          
          // Cache the result
          if (useCache) {
            await this.cache.set(cacheKey, {
              result: result.isBreached,
              breachCount: result.breachCount,
              timestamp: Date.now(),
              ttl: cacheTTL
            });
            this.cleanupExpiredCache();
          }

          return {
            ...result,
            fromCache: false,
            responseTime: Date.now() - startTime
          };
        } catch (error) {
          lastError = error as Error;
          this.consecutiveErrors++;
          
          // Increase backoff multiplier for rate limiting errors
          const errorMessage = error instanceof Error ? error.message : String(error);
          if (errorMessage.includes('429') || errorMessage.includes('rate limit')) {
            this.backoffMultiplier = Math.min(5, this.backoffMultiplier * 2);
          }
          
          // Don't retry on the last attempt
          if (attempt < retries) {
            await this.delay(retryDelay * Math.pow(2, attempt)); // Exponential backoff
          }
        }
      }

      // All retries failed
      return {
        isBreached: false,
        error: `Breach check failed after ${retries + 1} attempts: ${lastError?.message}`,
        fromCache: false,
        responseTime: Date.now() - startTime
      };

    } catch (error) {
      return {
        isBreached: false,
        error: `Breach check error: ${(error as Error).message}`,
        fromCache: false,
        responseTime: Date.now() - startTime
      };
    }
  }

  /**
   * Check multiple passwords with rate limiting
   */
  async checkMultiplePasswords(
    passwords: string[],
    options: BreachCheckOptions = {}
  ): Promise<Map<string, BreachCheckResult>> {
    const results = new Map<string, BreachCheckResult>();
    
    // Process passwords in batches to respect rate limits
    for (const password of passwords) {
      await this.waitForRateLimit();
      
      try {
        const result = await this.checkPassword(password, options);
        results.set(password, result);
      } catch (error) {
        results.set(password, {
          isBreached: false,
          error: `Failed to check password: ${(error as Error).message}`,
          fromCache: false,
          responseTime: 0
        });
      }
    }

    return results;
  }

  /**
   * Perform the actual breach check against HaveIBeenPwned API
   */
  private async performBreachCheck(
    password: string, 
    timeout: number
  ): Promise<{ isBreached: boolean; breachCount?: number }> {
    // Generate SHA-1 hash
    const hashHex = await this.generateSHA1Hash(password);
    const prefix = hashHex.substring(0, 5);
    const suffix = hashHex.substring(5);

    // Create abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const endpoint = `https://api.pwnedpasswords.com/range/${prefix}`;
      let response: Response;

      try {
        response = await fetch(endpoint, {
          headers: {
            'Add-Padding': 'true'
          },
          signal: controller.signal
        });
      } catch (firstError) {
        const firstMessage = firstError instanceof Error ? firstError.message : String(firstError);

        // Some WebView/browser environments can fail on custom headers.
        // Retry once without headers.
        if (firstMessage.toLowerCase().includes('load failed') || firstMessage.toLowerCase().includes('failed to fetch')) {
          response = await fetch(endpoint, {
            signal: controller.signal
          });
        } else {
          throw firstError;
        }
      }

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`API request failed with status ${response.status}: ${response.statusText}`);
      }

      const text = await response.text();
      const lines = text.split('\n');
      
      for (const line of lines) {
        const [hashSuffix, countStr] = line.split(':');
        if (hashSuffix?.trim() === suffix) {
          return {
            isBreached: true,
            breachCount: parseInt(countStr.trim(), 10)
          };
        }
      }

      return { isBreached: false };

    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new Error(`Request timed out after ${timeout}ms`);
        }
        if (error.message.toLowerCase().includes('load failed') || error.message.toLowerCase().includes('failed to fetch')) {
          throw new Error('Network request failed (connection blocked, offline, or WebView restriction)');
        }
        throw error;
      }
      throw new Error('Unknown error occurred during breach check');
    }
  }

  /**
   * Generate SHA-1 hash for password
   */
  private async generateSHA1Hash(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  /**
   * Create cache key for password
   */
  private async createCacheKey(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + 'breach-check-salt');
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }



  /**
   * Clean up expired cache entries
   */
  private cleanupExpiredCache(): void {
    this.cache.cleanup();
  }

  /**
   * Wait for rate limit compliance with burst limiting and adaptive backoff
   */
  private async waitForRateLimit(): Promise<void> {
    const now = Date.now();
    
    // Clean up old request times outside burst window
    this.requestTimes = this.requestTimes.filter(time => now - time < this.burstWindow);
    
    // Check burst limit
    if (this.requestTimes.length >= this.burstLimit) {
      const oldestRequest = Math.min(...this.requestTimes);
      const waitTime = this.burstWindow - (now - oldestRequest);
      if (waitTime > 0) {
        await this.delay(waitTime);
      }
    }
    
    // Apply standard rate limiting with adaptive backoff
    const timeSinceLastRequest = now - this.lastRequestTime;
    const adaptiveDelay = this.rateLimitDelay * this.backoffMultiplier;
    
    if (timeSinceLastRequest < adaptiveDelay) {
      await this.delay(adaptiveDelay - timeSinceLastRequest);
    }
    
    // Record this request time
    this.lastRequestTime = Date.now();
    this.requestTimes.push(this.lastRequestTime);
  }

  /**
   * Utility delay function
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; hitRate: number } {
    return {
      size: this.cache.size(),
      hitRate: 0 // Would need to track hits/misses for accurate calculation
    };
  }

  /**
   * Clear the cache
   */
  clearCache(): void {
    this.cache.clear();
  }
}

// Export singleton instance
export const breachChecker = new EnhancedBreachChecker();

// Export convenience functions
export const checkPasswordBreach = (password: string, options?: BreachCheckOptions) => 
  breachChecker.checkPassword(password, options);

export const checkMultiplePasswordBreaches = (passwords: string[], options?: BreachCheckOptions) =>
  breachChecker.checkMultiplePasswords(passwords, options);