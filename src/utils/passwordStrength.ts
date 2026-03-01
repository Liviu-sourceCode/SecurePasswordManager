export interface PasswordStrengthResult {
  score: number; // 0-100
  level: 'very-weak' | 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';
  entropy: number;
  requirements: {
    length: boolean;
    uppercase: boolean;
    lowercase: boolean;
    numbers: boolean;
    symbols: boolean;
    commonPassword: boolean;
    noUsername: boolean;
    noServiceName: boolean;
  };
  suggestions: string[];
  patterns: {
    hasAdvancedPatterns: boolean;
    hasKeyboardPatterns: boolean;
    hasLeetSpeak: boolean;
  };
}

export interface ContextualFactors {
  username?: string;
  email?: string;
  serviceName?: string;
  previousPasswords?: string[];
}

const COMMON_PASSWORDS = [
  'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
  'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'dragon',
  'master', 'login', 'pass', 'hello', 'guest', 'admin123'
];

// Advanced pattern detection for sophisticated attacks
const ADVANCED_PATTERNS = [
  /(.{3,})\1+/g,           // Repeated substrings (3+ chars)
  /^(.)\1*$/,             // All same character (enhanced)
  /(.).*\1.*\1.*\1/,      // Character appears 4+ times
  /^(19|20)\d{2}$/,       // Years (1900-2099)
  /^(0[1-9]|1[0-2])[0-3]\d$/,  // Dates (MMDD format)
  /^[a-z]+\d+$/i,         // Dictionary word + numbers
  /^\d+[a-z]+$/i,         // Numbers + dictionary word
  /^[a-z]+[!@#$%^&*]+$/i, // Dictionary word + symbols
  /^[!@#$%^&*]+[a-z]+$/i, // Symbols + dictionary word
  /(.)\1(.)\2/,           // AABB pattern
  /^(.)(.)(.)\3\2\1$/,    // Palindrome pattern
];

// Keyboard pattern detection with spatial awareness
const KEYBOARD_ADJACENCY_GRAPH: Record<string, string[]> = {
  '1': ['2', 'q'], '2': ['1', '3', 'q', 'w'], '3': ['2', '4', 'w', 'e'], '4': ['3', '5', 'e', 'r'], '5': ['4', '6', 'r', 't'],
  '6': ['5', '7', 't', 'y'], '7': ['6', '8', 'y', 'u'], '8': ['7', '9', 'u', 'i'], '9': ['8', '0', 'i', 'o'], '0': ['9', '-', 'o', 'p'],
  'q': ['1', '2', 'w', 'a'], 'w': ['q', 'e', '2', '3', 'a', 's'], 'e': ['w', 'r', '3', '4', 's', 'd'], 'r': ['e', 't', '4', '5', 'd', 'f'],
  't': ['r', 'y', '5', '6', 'f', 'g'], 'y': ['t', 'u', '6', '7', 'g', 'h'], 'u': ['y', 'i', '7', '8', 'h', 'j'], 'i': ['u', 'o', '8', '9', 'j', 'k'],
  'o': ['i', 'p', '9', '0', 'k', 'l'], 'p': ['o', '0', 'l'],
  'a': ['q', 'w', 's', 'z'], 's': ['a', 'd', 'w', 'e', 'z', 'x'], 'd': ['s', 'f', 'e', 'r', 'x', 'c'], 'f': ['d', 'g', 'r', 't', 'c', 'v'],
  'g': ['f', 'h', 't', 'y', 'v', 'b'], 'h': ['g', 'j', 'y', 'u', 'b', 'n'], 'j': ['h', 'k', 'u', 'i', 'n', 'm'], 'k': ['j', 'l', 'i', 'o', 'm'],
  'l': ['k', 'o', 'p'],
  'z': ['a', 's', 'x'], 'x': ['z', 'c', 's', 'd'], 'c': ['x', 'v', 'd', 'f'], 'v': ['c', 'b', 'f', 'g'], 'b': ['v', 'n', 'g', 'h'],
  'n': ['b', 'm', 'h', 'j'], 'm': ['n', 'j', 'k']
};

// Common keyboard sequences
const KEYBOARD_PATTERNS = [
  'qwerty', 'qwertyuiop', 'asdf', 'asdfghjkl', 'zxcv', 'zxcvbnm',
  '1234', '12345', '123456', '1234567', '12345678', '123456789',
  'abcd', 'abcde', 'abcdef', 'abcdefg', 'abcdefgh', 'abcdefghi',
  'qwer', 'wert', 'erty', 'rtyu', 'tyui', 'yuio', 'uiop',
  'asdf', 'sdfg', 'dfgh', 'fghj', 'ghjk', 'hjkl',
  'zxcv', 'xcvb', 'cvbn', 'vbnm'
];

// Extended common passwords with variations
const EXTENDED_COMMON_PASSWORDS = [
  ...COMMON_PASSWORDS,
  'password1', 'password12', 'password123', 'password1234',
  'welcome1', 'welcome123', 'admin1234', 'qwerty123',
  'abc12345', 'password!', 'password@', 'password#',
  'summer2024', 'winter2024', 'spring2024', 'fall2024',
  'facebook', 'google', 'amazon', 'microsoft', 'apple',
  'iloveyou', 'sunshine', 'princess', 'football', 'baseball',
  'trustno1', 'superman', 'batman', 'jordan23', 'charlie'
];

/**
 * Calculate password entropy based on character set diversity and length
 */
function calculateEntropy(password: string): number {
  if (!password) return 0;
  
  const charset = new Set(password);
  const charsetSize = charset.size;
  
  // Estimate character space based on actual characters used
  let estimatedCharSpace = 0;
  if (/[a-z]/.test(password)) estimatedCharSpace += 26;
  if (/[A-Z]/.test(password)) estimatedCharSpace += 26;
  if (/\d/.test(password)) estimatedCharSpace += 10;
  if (/[^A-Za-z0-9]/.test(password)) estimatedCharSpace += 32; // Common symbols
  
  // Use the larger of actual charset or estimated space
  const effectiveCharSpace = Math.max(charsetSize, estimatedCharSpace);
  
  return password.length * Math.log2(effectiveCharSpace);
}

/**
 * Check for advanced patterns that indicate weak passwords
 */
function checkAdvancedPatterns(password: string): { hasPattern: boolean; penalty: number } {
  let penalty = 0;
  let hasPattern = false;
  
  // Check advanced patterns
  for (const pattern of ADVANCED_PATTERNS) {
    if (pattern.test(password)) {
      penalty += 15;
      hasPattern = true;
      break; // Only apply penalty once for patterns
    }
  }
  
  // Check keyboard patterns
  const lowerPassword = password.toLowerCase();
  
  // 1. Check for standard sequences (e.g., qwerty)
  for (const keyboardPattern of KEYBOARD_PATTERNS) {
    if (lowerPassword.includes(keyboardPattern)) {
      penalty += 20;
      hasPattern = true;
      break;
    }
  }

  // 2. Check for spatial patterns (e.g., 'qaz', 'wsx') using adjacency graph
  let spatialPatternCount = 0;
  for (let i = 0; i < lowerPassword.length - 2; i++) {
    const c1 = lowerPassword[i];
    const c2 = lowerPassword[i+1];
    const c3 = lowerPassword[i+2];
    
    // Check if c2 is adjacent to c1, and c3 is adjacent to c2
    if (KEYBOARD_ADJACENCY_GRAPH[c1]?.includes(c2) && KEYBOARD_ADJACENCY_GRAPH[c2]?.includes(c3)) {
      spatialPatternCount++;
    }
  }
  
  if (spatialPatternCount > 0) {
      penalty += (spatialPatternCount * 10);
      hasPattern = true;
  }

  
  // Check for extended common passwords
  if (EXTENDED_COMMON_PASSWORDS.includes(lowerPassword)) {
    penalty += 30;
    hasPattern = true;
  }
  
  // Check for simple substitutions (l33t speak)
  const leetPassword = password
    .replace(/[@4]/g, 'a')
    .replace(/[3]/g, 'e')
    .replace(/[1!]/g, 'i')
    .replace(/[0]/g, 'o')
    .replace(/[5$]/g, 's')
    .replace(/[7]/g, 't')
    .toLowerCase();
    
  if (EXTENDED_COMMON_PASSWORDS.includes(leetPassword)) {
    penalty += 25;
    hasPattern = true;
  }
  
  return { hasPattern, penalty };
}

/**
 * Analyze contextual weaknesses in passwords
 */
function analyzeContextualWeakness(
  password: string, 
  context: ContextualFactors
): { penalty: number; hasServiceName: boolean; detectedPatterns: string[] } {
  let penalty = 0;
  let hasServiceName = false;
  const detectedPatterns: string[] = [];
  const passwordLower = password.toLowerCase();
  
  // Check against username variations
  if (context.username) {
    const username = context.username.toLowerCase();
    const variations = [
      username,
      username.split('').reverse().join(''), // Reversed
      username.replace(/[aeiou]/gi, ''), // Remove vowels
      username.substring(0, Math.floor(username.length / 2)), // First half
      username.substring(Math.floor(username.length / 2)), // Second half
    ];
    
    for (const variation of variations) {
      if (variation.length >= 3 && passwordLower.includes(variation)) {
        penalty += 20;
        detectedPatterns.push(`Contains username variation: ${variation}`);
        break;
      }
    }
  }
  
  // Check against email parts
  if (context.email) {
    const emailParts = context.email.toLowerCase().split('@');
    const localPart = emailParts[0];
    const domain = emailParts[1]?.split('.')[0];
    
    if (localPart && localPart.length >= 3 && passwordLower.includes(localPart)) {
      penalty += 15;
      detectedPatterns.push('Contains email local part');
    }
    
    if (domain && domain.length >= 3 && passwordLower.includes(domain)) {
      penalty += 10;
      detectedPatterns.push('Contains email domain');
    }
  }
  
  // Check against service name
  if (context.serviceName) {
    const serviceName = context.serviceName.toLowerCase();
    if (serviceName.length >= 3 && passwordLower.includes(serviceName)) {
      penalty += 15;
      hasServiceName = true;
      detectedPatterns.push(`Contains service name: ${serviceName}`);
    }
    
    // Check for common service variations
    const serviceVariations = [
      serviceName + '123',
      serviceName + '1',
      '123' + serviceName,
      serviceName + '!',
      serviceName + '@'
    ];
    
    for (const variation of serviceVariations) {
      if (passwordLower === variation) {
        penalty += 25;
        hasServiceName = true;
        detectedPatterns.push(`Matches service name pattern: ${variation}`);
        break;
      }
    }
  }
  
  // Check against previous passwords (similarity)
  if (context.previousPasswords) {
    for (const prevPassword of context.previousPasswords) {
      const similarity = calculateSimilarity(password, prevPassword);
      if (similarity > 0.7) { // 70% similarity threshold
        penalty += 20;
        detectedPatterns.push('Too similar to previous password');
        break;
      }
    }
  }
  
  return { penalty, hasServiceName: !hasServiceName, detectedPatterns };
}

/**
 * Calculate similarity between two strings (simple Levenshtein-based)
 */
function calculateSimilarity(str1: string, str2: string): number {
  const longer = str1.length > str2.length ? str1 : str2;
  const shorter = str1.length > str2.length ? str2 : str1;
  
  if (longer.length === 0) return 1.0;
  
  const editDistance = levenshteinDistance(longer, shorter);
  return (longer.length - editDistance) / longer.length;
}

/**
 * Calculate Levenshtein distance between two strings
 */
function levenshteinDistance(str1: string, str2: string): number {
  const matrix = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));
  
  for (let i = 0; i <= str1.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= str2.length; j++) matrix[j][0] = j;
  
  for (let j = 1; j <= str2.length; j++) {
    for (let i = 1; i <= str1.length; i++) {
      const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1,     // deletion
        matrix[j - 1][i] + 1,     // insertion
        matrix[j - 1][i - 1] + indicator // substitution
      );
    }
  }
  
  return matrix[str2.length][str1.length];
}

/**
 * Main password strength analysis function with enhanced scoring and contextual analysis
 */
export function analyzePasswordStrength(
  password: string, 
  context?: ContextualFactors
): PasswordStrengthResult {
  if (!password) {
    return {
      score: 0,
      level: 'very-weak',
      entropy: 0,
      requirements: {
        length: false,
        uppercase: false,
        lowercase: false,
        numbers: false,
        symbols: false,
        commonPassword: true,
        noUsername: true,
        noServiceName: true,
      },
      suggestions: ['Password is required'],
      patterns: {
        hasAdvancedPatterns: false,
        hasKeyboardPatterns: false,
        hasLeetSpeak: false,
      }
    };
  }

  let score = 0;
  const suggestions: string[] = [];
  
  // Calculate entropy
  const entropy = calculateEntropy(password);
  
  // Basic requirements
  const hasLowercase = /[a-z]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSymbols = /[^A-Za-z0-9]/.test(password);
  const hasMinLength = password.length >= 8;
  
  // Length scoring (enhanced)
  if (password.length >= 16) score += 30;
  else if (password.length >= 12) score += 25;
  else if (password.length >= 8) score += 15;
  else if (password.length >= 6) score += 5;
  else suggestions.push('Use at least 8 characters');
  
  // Character variety scoring
  if (hasLowercase) score += 10;
  else suggestions.push('Include lowercase letters');
  
  if (hasUppercase) score += 10;
  else suggestions.push('Include uppercase letters');
  
  if (hasNumbers) score += 10;
  else suggestions.push('Include numbers');
  
  if (hasSymbols) score += 15;
  else suggestions.push('Include special characters');
  
  // Check for common passwords
  const isCommonPassword = EXTENDED_COMMON_PASSWORDS.includes(password.toLowerCase());
  if (isCommonPassword) {
    score -= 30;
    suggestions.push('Avoid common passwords');
  }
  
  // Check for advanced patterns
  const { hasPattern: hasAdvancedPattern, penalty: patternPenalty } = checkAdvancedPatterns(password);
  score -= patternPenalty;
  
  if (hasAdvancedPattern) {
    suggestions.push('Avoid predictable patterns');
  }
  
  // Contextual analysis
  let hasUsername = true;
  let hasServiceName = true;
  
  if (context) {
    const contextualResult = analyzeContextualWeakness(password, context);
    score -= contextualResult.penalty;
    hasUsername = contextualResult.hasServiceName; // Note: this is inverted in the function
    hasServiceName = contextualResult.hasServiceName;
    
    if (contextualResult.penalty > 0) {
      suggestions.push('Avoid using personal information in passwords');
    }
  }
  
  // Entropy bonus
  if (entropy > 60) score += 15;
  else if (entropy > 40) score += 10;
  else if (entropy > 20) score += 5;
  
  // Character variety bonus
  const charTypes = [hasLowercase, hasUppercase, hasNumbers, hasSymbols].filter(Boolean).length;
  if (charTypes >= 4) score += 10;
  else if (charTypes >= 3) score += 5;
  
  // Ensure score is within bounds
  score = Math.max(0, Math.min(100, score));
  
  // Determine level
  let level: PasswordStrengthResult['level'];
  if (score >= 90) level = 'very-strong';
  else if (score >= 75) level = 'strong';
  else if (score >= 60) level = 'good';
  else if (score >= 40) level = 'fair';
  else if (score >= 20) level = 'weak';
  else level = 'very-weak';
  
  // Pattern analysis
  const hasKeyboardPatterns = KEYBOARD_PATTERNS.some(pattern => 
    password.toLowerCase().includes(pattern)
  );
  
  const hasLeetSpeak = password !== password
    .replace(/[@4]/g, 'a')
    .replace(/[3]/g, 'e')
    .replace(/[1!]/g, 'i')
    .replace(/[0]/g, 'o')
    .replace(/[5$]/g, 's')
    .replace(/[7]/g, 't');
  
  return {
    score,
    level,
    entropy,
    requirements: {
      length: hasMinLength,
      uppercase: hasUppercase,
      lowercase: hasLowercase,
      numbers: hasNumbers,
      symbols: hasSymbols,
      commonPassword: !isCommonPassword,
      noUsername: hasUsername,
      noServiceName: hasServiceName,
    },
    suggestions,
    patterns: {
      hasAdvancedPatterns: hasAdvancedPattern,
      hasKeyboardPatterns,
      hasLeetSpeak,
    }
  };
}

export function getStrengthColor(scoreOrLevel: number | PasswordStrengthResult['level'], type: 'text' | 'bg' | 'color' = 'text'): string {
  let level: PasswordStrengthResult['level'];
  
  if (typeof scoreOrLevel === 'number') {
    const score = scoreOrLevel;
    if (score >= 90) level = 'very-strong';
    else if (score >= 75) level = 'strong';
    else if (score >= 60) level = 'good';
    else if (score >= 40) level = 'fair';
    else if (score >= 20) level = 'weak';
    else level = 'very-weak';
  } else {
    level = scoreOrLevel;
  }

  if (type === 'bg') {
    switch (level) {
      case 'very-weak': return 'bg-red-600';
      case 'weak': return 'bg-orange-600';
      case 'fair': return 'bg-amber-600';
      case 'good': return 'bg-lime-600';
      case 'strong': return 'bg-green-600';
      case 'very-strong': return 'bg-emerald-600';
      default: return 'bg-gray-500';
    }
  } else if (type === 'color') {
    switch (level) {
      case 'very-weak': return '#dc2626';
      case 'weak': return '#ea580c';
      case 'fair': return '#d97706';
      case 'good': return '#65a30d';
      case 'strong': return '#16a34a';
      case 'very-strong': return '#059669';
      default: return '#6b7280';
    }
  } else {
    switch (level) {
      case 'very-weak': return 'text-red-400';
      case 'weak': return 'text-orange-400';
      case 'fair': return 'text-amber-400';
      case 'good': return 'text-lime-400';
      case 'strong': return 'text-green-400';
      case 'very-strong': return 'text-emerald-400';
      default: return 'text-gray-400';
    }
  }
}

export function getStrengthLabel(scoreOrLevel: number | PasswordStrengthResult['level']): string {
  let level: PasswordStrengthResult['level'];
  
  if (typeof scoreOrLevel === 'number') {
    const score = scoreOrLevel;
    if (score >= 90) level = 'very-strong';
    else if (score >= 75) level = 'strong';
    else if (score >= 60) level = 'good';
    else if (score >= 40) level = 'fair';
    else if (score >= 20) level = 'weak';
    else level = 'very-weak';
  } else {
    level = scoreOrLevel;
  }

  switch (level) {
    case 'very-weak': return 'Very Weak';
    case 'weak': return 'Weak';
    case 'fair': return 'Fair';
    case 'good': return 'Good';
    case 'strong': return 'Strong';
    case 'very-strong': return 'Very Strong';
    default: return 'Unknown';
  }
}