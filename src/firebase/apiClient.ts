import { getFirebaseAuth } from './client';

export class ApiError extends Error {
  status: number;
  data: any;

  constructor(message: string, status: number, data?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

export interface RequestOptions extends RequestInit {
  timeoutMs?: number;
}

let customTokenGetter: (() => Promise<string | null>) | null = null;

export function registerTokenGetter(getter: (() => Promise<string | null>) | null): void {
  customTokenGetter = getter;
}

/**
 * Executes an authenticated API request to the backend with the current user's Firebase ID token.
 */
export async function apiFetch<T = any>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  let token: string | null = null;

  if (customTokenGetter) {
    token = await customTokenGetter();
  }

  if (!token) {
    try {
      const auth = getFirebaseAuth();
      const currentUser = auth.currentUser;
      if (currentUser) {
        token = await currentUser.getIdToken();
      }
    } catch {
      // ignore
    }
  }

  if (!token) {
    throw new ApiError('Authentication required to perform this action.', 401);
  }

  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${token}`);
  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  const timeoutMs = options.timeoutMs ?? 45000;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  const signal = options.signal || controller.signal;

  try {
    const response = await fetch(endpoint, {
      ...options,
      headers,
      signal,
    });

    clearTimeout(id);

    const contentType = response.headers.get('content-type') || '';
    let responseData: any = null;

    if (contentType.includes('application/json')) {
      responseData = await response.json().catch(() => null);
    } else {
      responseData = await response.text().catch(() => null);
    }

    if (!response.ok) {
      const errorMessage =
        (responseData && typeof responseData === 'object' && responseData.error) ||
        (typeof responseData === 'string' && responseData) ||
        `Request failed with status ${response.status}`;
      throw new ApiError(errorMessage, response.status, responseData);
    }

    return responseData as T;
  } catch (err: any) {
    clearTimeout(id);
    if (err.name === 'AbortError') {
      throw new ApiError(`Request timed out after ${timeoutMs}ms`, 408);
    }
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(err?.message || 'Network request failed', 500);
  }
}
