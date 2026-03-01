export interface PasswordEntry {
  id: string;
  service: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface SecurityIssue {
  id: string;
  type: 'weak' | 'reused' | 'breached' | 'old' | 'warning';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  service: string;
}

export interface SecurityStats {
  total: number;
  weak: number;
  reused: number;
  breached: number;
  old: number;
  warnings: number;
  score: number;
}
