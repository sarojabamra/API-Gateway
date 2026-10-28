export type UserRole = 'admin' | 'analyst' | 'developer' | 'viewer';

export interface UserProfile {
  id: number;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
}

export interface TrafficLogItem {
  id: number;
  upstream_id?: number;
  ts: string;
  request_id: string;
  client_ip: string;
  user_sub?: string | null;
  user_role?: string | null;
  method: string;
  path: string;
  query_params?: string;
  status_code: number;
  latency_ms: number;
  req_size_bytes?: number;
  resp_size_bytes?: number;
  decision: 'allowed' | 'blocked' | 'rate_limited' | 'monitored' | string;
  block_reason?: string | null;
  owasp_id?: string | null;
  threat_score: number;
  anomaly_zscore?: number;
}

export interface AlertItem {
  id: number;
  upstream_id?: number;
  ts: string;
  updated_at?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  type: string;
  owasp_id: string;
  title: string;
  description?: string;
  client_ip: string;
  user_sub?: string | null;
  target_path: string;
  event_count: number;
  status: 'open' | 'investigating' | 'resolved' | 'false_positive' | string;
  assigned_to?: string | null;
}
