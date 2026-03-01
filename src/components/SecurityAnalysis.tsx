import { useState, useEffect } from 'react';
import { PasswordEntry, SecurityIssue, SecurityStats } from '../types';
import { analyzePasswordStrength } from '../utils/passwordStrength';
import { checkPasswordBreach } from '../utils/breachChecker';

interface SecurityAnalysisProps {
  entries: PasswordEntry[];
}

export function SecurityAnalysis({ entries }: SecurityAnalysisProps) {
  const [issues, setIssues] = useState<SecurityIssue[]>([]);
  const [stats, setStats] = useState<SecurityStats>({
    total: 0,
    weak: 0,
    reused: 0,
    breached: 0,
    old: 0,
    warnings: 0,
    score: 100
  });
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const calculatePasswordStrength = (password: string): number => {
    if (!password) return 0;
    return analyzePasswordStrength(password).score;
  };

  // Helper function to create a hash for caching (not for security, just for cache keys)
  const createCacheKey = async (password: string): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const checkPasswordBreachEnhanced = async (password: string): Promise<{ isBreached: boolean; breachCount?: number; error?: string }> => {
    try {
      const result = await checkPasswordBreach(password, {
        timeout: 8000,
        retries: 2,
        retryDelay: 1000,
        useCache: true,
        cacheTTL: 24 * 60 * 60 * 1000 // 24 hours
      });

      if (result.error) {
        console.warn('Breach check warning:', result.error);
      }

      return {
        isBreached: result.isBreached,
        breachCount: result.breachCount,
        error: result.error
      };
    } catch (error) {
      console.error('Error checking password breach:', error);
      return {
        isBreached: false,
        error: `Breach check failed: ${(error as Error).message}`
      };
    }
  };

  const analyzePasswords = async () => {
    setIsAnalyzing(true);
    const newIssues: SecurityIssue[] = [];

    // Precompute hash for each entry and group by hash to avoid plaintext keys and redundant checks
    const entriesWithHash = await Promise.all(
      entries.map(async (entry) => ({
        entry,
        hash: await createCacheKey(entry.password)
      }))
    );

    const groupByHash = new Map<string, { services: string[]; entries: PasswordEntry[] }>();
    for (const { entry, hash } of entriesWithHash) {
      const group = groupByHash.get(hash) || { services: [], entries: [] };
      group.services.push(entry.service);
      group.entries.push(entry);
      groupByHash.set(hash, group);
    }

    // Weak/reused/old checks
    for (const { entry, hash } of entriesWithHash) {
      const strength = calculatePasswordStrength(entry.password);
      const daysSinceUpdate = Math.floor(
        (Date.now() - new Date(entry.updated_at).getTime()) / (1000 * 60 * 60 * 24)
      );
      const services = groupByHash.get(hash)?.services || [];

      if (strength < 50) {
        newIssues.push({
          id: `weak-${entry.id}`,
          type: 'weak',
          severity: strength < 25 ? 'critical' : 'high',
          title: 'Weak Password',
          description: `Password strength: ${strength}%. This password should be updated.`,
          service: entry.service
        });
      }

      if (services.length > 1) {
        newIssues.push({
          id: `reused-${entry.id}`,
          type: 'reused',
          severity: 'high',
          title: 'Reused Password',
          description: `This password is used for ${services.length} services: ${services.join(', ')}.`,
          service: entry.service
        });
      }

      if (daysSinceUpdate > 365) {
        newIssues.push({
          id: `old-${entry.id}`,
          type: 'old',
          severity: daysSinceUpdate > 730 ? 'medium' : 'low',
          title: 'Old Password',
          description: `Password hasn't been updated for ${Math.floor(daysSinceUpdate / 30)} months.`,
          service: entry.service
        });
      }
    }

    // Enhanced breach checks per unique hash with improved error handling
    const uniqueChecks = Array.from(groupByHash.entries()).map(([hash, group]) => ({
      hash,
      samplePassword: group.entries[0].password
    }));
    
    const breachedByHash = new Map<string, { isBreached: boolean; breachCount?: number; error?: string }>();
    const concurrency = 3; // Reduced for better rate limiting
    
    for (let i = 0; i < uniqueChecks.length; i += concurrency) {
      const slice = uniqueChecks.slice(i, i + concurrency);
      const results = await Promise.all(
        slice.map(async ({ hash, samplePassword }) => {
          const result = await checkPasswordBreachEnhanced(samplePassword);
          return { hash, ...result };
        })
      );
      results.forEach(({ hash, isBreached, breachCount, error }) => 
        breachedByHash.set(hash, { isBreached, breachCount, error })
      );
    }

    // Add breach issues for affected entries with enhanced information
    for (const { entry, hash } of entriesWithHash) {
      const breachInfo = breachedByHash.get(hash);
      if (breachInfo?.isBreached) {
        const breachCountText = breachInfo.breachCount 
          ? ` (found ${breachInfo.breachCount.toLocaleString()} times)`
          : '';
        
        newIssues.push({
          id: `breached-${entry.id}`,
          type: 'breached',
          severity: 'critical',
          title: 'Breached Password',
          description: `This password has been found in data breaches${breachCountText}. Change it immediately.`,
          service: entry.service
        });
      } else if (breachInfo?.error) {
        // Add a warning for failed breach checks
        newIssues.push({
          id: `breach-check-failed-${entry.id}`,
          type: 'warning',
          severity: 'low',
          title: 'Breach Check Failed',
          description: `Could not verify if this password has been breached: ${breachInfo.error}`,
          service: entry.service
        });
      }
    }

    setIssues(newIssues);

    // Calculate stats with enhanced categories
    const newStats = {
      total: entries.length,
      weak: newIssues.filter(i => i.type === 'weak').length,
      reused: newIssues.filter(i => i.type === 'reused').length,
      breached: newIssues.filter(i => i.type === 'breached').length,
      old: newIssues.filter(i => i.type === 'old').length,
      warnings: newIssues.filter(i => i.type === 'warning').length,
      score: 0
    };

    // Calculate security score (0-100) with improved algorithm
    const criticalIssues = newIssues.filter(i => i.severity === 'critical').length;
    const highIssues = newIssues.filter(i => i.severity === 'high').length;
    const mediumIssues = newIssues.filter(i => i.severity === 'medium').length;
    const lowIssues = newIssues.filter(i => i.severity === 'low').length;

    // Enhanced scoring algorithm
    let score = 100;
    score -= criticalIssues * 25; // Increased penalty for critical issues
    score -= highIssues * 15;     // Increased penalty for high issues
    score -= mediumIssues * 8;    // Medium issues penalty
    score -= lowIssues * 3;       // Low issues penalty (including warnings)

    // Additional penalties for specific issue types
    score -= newStats.breached * 5;  // Extra penalty for breached passwords
    score -= newStats.reused * 3;    // Extra penalty for reused passwords

    // Bonus for having no critical issues
    if (criticalIssues === 0 && entries.length > 0) {
      score += 5;
    }

    newStats.score = Math.max(0, Math.min(100, score));
    setStats(newStats);
    setIsAnalyzing(false);
  };

  useEffect(() => {
    if (entries.length > 0) {
      analyzePasswords();
    } else {
      setIssues([]);
      setStats({
        total: 0,
        weak: 0,
        reused: 0,
        breached: 0,
        old: 0,
        warnings: 0,
        score: 100
      });
    }
  }, [entries]);

  const getScoreColor = (score: number): string => {
    if (score >= 80) return '#22c55e';
    if (score >= 60) return '#eab308';
    if (score >= 40) return '#f97316';
    return '#ef4444';
  };

  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      case 'low': return '#6b7280';
      default: return '#6b7280';
    }
  };

  const getIssueIcon = (type: string): string => {
    switch (type) {
      case 'weak': return '🔓';
      case 'reused': return '🔄';
      case 'breached': return '🚨';
      case 'old': return '⏰';
      default: return '⚠️';
    }
  };

  if (entries.length === 0) {
    return (
      <div className="security-analysis">
        <div className="security-header">
          <h3>Security Analysis</h3>
        </div>
        <div className="security-empty">
          <p>No passwords to analyze</p>
        </div>
      </div>
    );
  }

  return (
    <div className="security-analysis">
      <div className="security-header">
        <h3>Security Analysis</h3>
        <button
          onClick={analyzePasswords}
          disabled={isAnalyzing}
          className="btn btn-primary"
        >
          {isAnalyzing ? 'Analyzing...' : 'Refresh Analysis'}
        </button>
      </div>

      <div className="security-score">
        <div className="score-circle">
          <div 
            className="score-fill"
            style={{ 
              background: `conic-gradient(${getScoreColor(stats.score)} ${stats.score * 3.6}deg, rgba(255,255,255,0.1) 0deg)`
            }}
          >
            <div className="score-inner">
              <span className="score-number">{stats.score}</span>
              <span className="score-label">Security Score</span>
            </div>
          </div>
        </div>
        
        <div className="security-stats">
          <div className="stat-item">
            <span className="stat-number">{stats.total}</span>
            <span className="stat-label">Total Passwords</span>
          </div>
          <div className="stat-item">
            <span className="stat-number" style={{ color: '#ef4444' }}>{stats.weak}</span>
            <span className="stat-label">Weak</span>
          </div>
          <div className="stat-item">
            <span className="stat-number" style={{ color: '#f97316' }}>{stats.reused}</span>
            <span className="stat-label">Reused</span>
          </div>
          <div className="stat-item">
            <span className="stat-number" style={{ color: '#ef4444' }}>{stats.breached}</span>
            <span className="stat-label">Breached</span>
          </div>
          <div className="stat-item">
            <span className="stat-number" style={{ color: '#eab308' }}>{stats.old}</span>
            <span className="stat-label">Old</span>
          </div>
        </div>
      </div>

      {issues.length > 0 && (
        <div className="security-issues">
          <h4>Security Issues ({issues.length})</h4>
          <div className="issues-list">
            {issues.map(issue => (
              <div key={issue.id} className="issue-item">
                <div className="issue-icon">{getIssueIcon(issue.type)}</div>
                <div className="issue-content">
                  <div className="issue-header">
                    <span className="issue-title">{issue.title}</span>
                    <span 
                      className="issue-severity"
                      style={{ color: getSeverityColor(issue.severity) }}
                    >
                      {issue.severity.toUpperCase()}
                    </span>
                  </div>
                  <div className="issue-service">{issue.service}</div>
                  <div className="issue-description">{issue.description}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {issues.length === 0 && !isAnalyzing && (
        <div className="security-good">
          <div className="good-icon">🛡️</div>
          <h4>Great Security!</h4>
          <p>No security issues found with your passwords.</p>
        </div>
      )}
    </div>
  );
}

export default SecurityAnalysis;