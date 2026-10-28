import { useGatewayStore } from '../store/useGatewayStore';

const API_BASE = '/api/v1';

export async function apiFetch<T = any>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = useGatewayStore.getState().token;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errDetail = `HTTP ${response.status}`;
    try {
      const errJson = await response.json();
      const raw = errJson.detail ?? errJson.message ?? errDetail;
      if (typeof raw === 'string') {
        errDetail = raw;
      } else if (Array.isArray(raw)) {
        errDetail = raw
          .map((item: any) =>
            typeof item === 'string'
              ? item
              : `${(item.loc || []).slice(-1)[0] || 'field'}: ${item.msg || JSON.stringify(item)}`
          )
          .join('; ');
      } else if (raw && typeof raw === 'object') {
        errDetail = JSON.stringify(raw);
      }
    } catch {
      // ignore
    }
    throw new Error(errDetail);
  }

  return response.json();
}

function parseTimestamp(ts?: string | number | Date | null): Date | null {
  if (!ts) return null;
  if (ts instanceof Date) return isNaN(ts.getTime()) ? null : ts;
  if (typeof ts === 'number') return new Date(ts);
  const str = String(ts).trim();
  if (!str) return null;
  const hasTz = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(str);
  const normalized = hasTz ? str : `${str}Z`;
  const d = new Date(normalized);
  return isNaN(d.getTime()) ? null : d;
}

export function formatTimeIST(ts?: string | number | Date | null): string {
  const d = parseTimestamp(ts);
  if (!d) return '—';
  const formatted = new Intl.DateTimeFormat('en-IN', {
    timeZone: 'Asia/Kolkata',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  }).format(d);
  return `${formatted.toUpperCase()} IST`;
}

export function formatDateTimeIST(ts?: string | number | Date | null): string {
  const d = parseTimestamp(ts);
  if (!d) return '—';
  const formatted = new Intl.DateTimeFormat('en-IN', {
    timeZone: 'Asia/Kolkata',
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  }).format(d);
  return `${formatted.toUpperCase()} IST`;
}

