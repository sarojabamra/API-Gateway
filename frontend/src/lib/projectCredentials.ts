/** Browser-local test credentials for the selected API project (JWT + X-API-Key). */

const jwtStorageKey = (projectId: number) => `sentinel_project_jwt_${projectId}`;
const apiKeyStorageKey = (projectId: number) => `sentinel_project_api_key_${projectId}`;
const legacySimJwtKey = (projectId: number) => `sentinel_sim_jwt_${projectId}`;

const safeGet = (key: string) => {
  try {
    return localStorage.getItem(key) || '';
  } catch {
    return '';
  }
};

const safeSet = (key: string, value: string) => {
  try {
    if (value.trim()) {
      localStorage.setItem(key, value.trim());
    } else {
      localStorage.removeItem(key);
    }
  } catch {
    // ignore quota / private mode
  }
};

export const readProjectJwt = (projectId: number | null): string => {
  if (!projectId) return '';
  const current = safeGet(jwtStorageKey(projectId));
  if (current) return current;
  const legacy = safeGet(legacySimJwtKey(projectId));
  if (legacy) {
    safeSet(jwtStorageKey(projectId), legacy);
    return legacy;
  }
  return '';
};

export const writeProjectJwt = (projectId: number | null, token: string) => {
  if (!projectId) return;
  safeSet(jwtStorageKey(projectId), token);
  // Keep the older simulator key in sync so nothing else reading it goes stale.
  safeSet(legacySimJwtKey(projectId), token);
};

export const readProjectApiKey = (projectId: number | null): string => {
  if (!projectId) return '';
  return safeGet(apiKeyStorageKey(projectId));
};

export const writeProjectApiKey = (projectId: number | null, apiKey: string) => {
  if (!projectId) return;
  safeSet(apiKeyStorageKey(projectId), apiKey);
};

export const clearProjectCredentials = (projectId: number | null) => {
  if (!projectId) return;
  writeProjectJwt(projectId, '');
  writeProjectApiKey(projectId, '');
};

export const clearAllProjectCredentials = () => {
  try {
    const keys: string[] = [];
    for (let i = 0; i < localStorage.length; i += 1) {
      const key = localStorage.key(i);
      if (
        key &&
        (key.startsWith('sentinel_project_jwt_') ||
          key.startsWith('sentinel_project_api_key_') ||
          key.startsWith('sentinel_sim_jwt_'))
      ) {
        keys.push(key);
      }
    }
    keys.forEach((key) => localStorage.removeItem(key));
  } catch {
    // ignore
  }
};

/** Headers for browser-side calls through `/gw/...` (Inventory Test Route). */
export const buildGatewayAuthHeaders = (projectId: number | null): Record<string, string> => {
  const headers: Record<string, string> = {};
  const jwt = readProjectJwt(projectId).trim();
  const apiKey = readProjectApiKey(projectId).trim();
  if (jwt) headers.Authorization = `Bearer ${jwt}`;
  if (apiKey) headers['X-API-Key'] = apiKey;
  return headers;
};
