import axios from 'axios';
import type { Site } from '../types/api';

export const apiClient = axios.create({
  baseURL: '/api',
  timeout: 10_000,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('cheesewaf-token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

type Envelope<T> = {
  data?: T;
  error?: {
    code: string;
    message: string;
  };
};

async function unwrap<T>(promise: Promise<{ data: Envelope<T> }>): Promise<T> {
  const response = await promise;
  if (response.data.error) {
    throw new Error(response.data.error.message);
  }
  return response.data.data as T;
}

export function login(username: string, password: string) {
  return unwrap<{ token: string; user: { username: string; role: string } }>(
    apiClient.post('/auth/login', { username, password }),
  );
}

export function setupAdmin(username: string, password: string, adminListen: string) {
  return unwrap<{ user: { username: string; role: string } }>(
    apiClient.post('/setup', { username, password, admin_listen: adminListen }),
  );
}

export function fetchSites() {
  return unwrap<Site[]>(apiClient.get('/sites'));
}

export function createSite(site: Partial<Site>) {
  return unwrap<Site>(apiClient.post('/sites', site));
}

export function fetchStats() {
  return unwrap<Record<string, unknown>>(apiClient.get('/stats'));
}
