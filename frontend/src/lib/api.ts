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
      errDetail = errJson.detail || errJson.message || errDetail;
    } catch {
      // ignore
    }
    throw new Error(errDetail);
  }

  return response.json();
}
