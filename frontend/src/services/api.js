import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  login: (username, password) => api.post('/auth/login', { username, password }),
  register: (data) => api.post('/auth/register', data),
  getMe: () => api.get('/auth/me'),
};

export const dlpAPI = {
  getPolicies: () => api.get('/dlp/policies'),
  getPolicy: (id) => api.get(`/dlp/policies/${id}`),
  createPolicy: (data) => api.post('/dlp/policies', data),
  updatePolicy: (id, data) => api.put(`/dlp/policies/${id}`, data),
  deletePolicy: (id) => api.delete(`/dlp/policies/${id}`),
  getEvents: (params) => api.get('/dlp/events', { params }),
  getEvent: (id) => api.get(`/dlp/events/${id}`),
  createIncident: (eventId) => api.post(`/dlp/events/${eventId}/create-incident`),
  getStats: () => api.get('/dlp/stats/summary'),
  testPattern: (pattern, content) => api.post('/dlp/test-pattern', { pattern, content }),
};

export const siemAPI = {
  getEvents: (params) => api.get('/siem/events', { params }),
  getEvent: (id) => api.get(`/siem/events/${id}`),
  searchEvents: (query, limit) => api.get('/siem/events/search', { params: { query, limit } }),
  getSources: () => api.get('/siem/sources'),
  getEventTypes: (source) => api.get('/siem/event-types', { params: { source } }),
  getStats: () => api.get('/siem/stats/summary'),
  getLogs: (params) => api.get('/siem/logs', { params }),
};

export const incidentsAPI = {
  getIncidents: (params) => api.get('/incidents', { params }),
  getIncident: (id) => api.get(`/incidents/${id}`),
  createIncident: (data) => api.post('/incidents', data),
  updateIncident: (id, data) => api.put(`/incidents/${id}`, data),
  deleteIncident: (id) => api.delete(`/incidents/${id}`),
  getDashboardStats: () => api.get('/incidents/stats/dashboard'),
  getBySource: () => api.get('/incidents/by-source'),
};

export default api;
