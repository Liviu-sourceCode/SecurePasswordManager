/**
 * Password Security Analyzer Utility
 * Uses the same evaluation mechanism as the SecurityAnalysis component
 */

export interface PasswordAnalysisResult {
  score: number;
  isWeak: boolean;
  severity: 'critical' | 'high' | 'medium' | 'strong';
  details: {
    length: number;
    hasLowercase: boolean;
    hasUppercase: boolean;
    hasNumbers: boolean;
    hasSpecialChars: boolean;
    hasRepeatingPatterns: boolean;
    isOnlyNumbers: boolean;
    isOnlyLetters: boolean;
  };
}

/**
 * Calculates password strength using the same algorithm as SecurityAnalysis component
 * @param password - The password to analyze
 * @returns Password strength score (0-100)
 */
export function calculatePasswordStrength(password: string): number {
  if (!password) return 0;
  
  let score = 0;
  
  // Length scoring
  if (password.length >= 12) score += 25;
  else if (password.length >= 8) score += 15;
  else if (password.length >= 6) score += 5;
  
  // Character variety
  if (/[a-z]/.test(password)) score += 15;
  if (/[A-Z]/.test(password)) score += 15;
  if (/\d/.test(password)) score += 15;
  if (/[^\w\s]/.test(password)) score += 20;
  
  // Bonus for longer passwords
  if (password.length >= 16) score += 10;
  
  // Penalty for common patterns
  if (/(..).*\1/.test(password)) score -= 10;
  if (/^\d+$/.test(password)) score -= 20;
  if (/^[a-zA-Z]+$/.test(password)) score -= 10;
  
  return Math.max(0, Math.min(100, score));
}

/**
 * Determines if a password is considered weak using the same criteria as SecurityAnalysis
 * @param password - The password to evaluate
 * @returns true if password is weak (score < 50)
 */
export function isWeakPassword(password: string): boolean {
  const strength = calculatePasswordStrength(password);
  return strength < 50;
}

/**
 * Provides comprehensive password analysis with detailed feedback
 * @param password - The password to analyze
 * @returns Complete analysis result with score, weakness status, and feedback
 */
export function analyzePassword(password: string): PasswordAnalysisResult {
  if (!password) {
    return {
      score: 0,
      isWeak: true,
      severity: 'critical',
      details: {
        length: 0,
        hasLowercase: false,
        hasUppercase: false,
        hasNumbers: false,
        hasSpecialChars: false,
        hasRepeatingPatterns: false,
        isOnlyNumbers: false,
        isOnlyLetters: false
      }
    };
  }

  const score = calculatePasswordStrength(password);
  const isWeak = score < 50;
  
  // Analyze password characteristics
  const details = {
    length: password.length,
    hasLowercase: /[a-z]/.test(password),
    hasUppercase: /[A-Z]/.test(password),
    hasNumbers: /\d/.test(password),
    hasSpecialChars: /[^\w\s]/.test(password),
    hasRepeatingPatterns: /(..).*\1/.test(password),
    isOnlyNumbers: /^\d+$/.test(password),
    isOnlyLetters: /^[a-zA-Z]+$/.test(password)
  };

  // Determine severity based on score (same as SecurityAnalysis component)
  let severity: 'critical' | 'high' | 'medium' | 'strong';
  if (score < 25) severity = 'critical';
  else if (score < 50) severity = 'high';
  else if (score < 75) severity = 'medium';
  else severity = 'strong';

  return {
    score,
    isWeak,
    severity,
    details
  };
}

/**
 * Formats the analysis result into a human-readable string
 * @param result - The password analysis result
 * @returns Formatted analysis summary
 */
export function formatAnalysisResult(result: PasswordAnalysisResult): string {
  const { score, isWeak, severity } = result;
  
  let summary = `Password Strength: ${score}% (${severity.toUpperCase()})`;
  
  if (isWeak) {
    summary += '\n⚠️  This password is considered WEAK';
  } else {
    summary += '\n✅ This password meets security requirements';
  }
  
  return summary;
}

/**
 * Quick check if password meets minimum security requirements
 * @param password - The password to check
 * @returns true if password is not weak
 */
export function meetsSecurityRequirements(password: string): boolean {
  return !isWeakPassword(password);
}