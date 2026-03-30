import api from './client';

export const login = async (email: string, password: string) => {
  const { data } = await api.post('/auth/login', { email, password });
  localStorage.setItem('access_token', data.access_token);
  localStorage.setItem('refresh_token', data.refresh_token);
  return data;
};

export const register = async (data: {
  email: string;
  password: string;
  name: string;
}) => {
  const response = await api.post('/auth/register', data);
  return response.data;
};

export const getMe = async () => {
  const { data } = await api.get('/auth/me');
  return data;
};

export const refreshToken = async (refresh_token: string) => {
  const { data } = await api.post('/auth/refresh', { refresh_token });
  return data;
};

export const logout = () => {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
};
