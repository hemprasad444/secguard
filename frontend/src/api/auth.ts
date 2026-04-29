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

export const changePassword = async (current_password: string, new_password: string) => {
  const { data } = await api.post('/auth/change-password', { current_password, new_password });
  return data;
};

export const adminCreateUser = async (body: {
  email: string;
  name: string;
  role: string;
  password?: string;
}) => {
  const { data } = await api.post('/users/', body);
  return data as {
    user: { id: string; email: string; name: string; role: string };
    temporary_password: string;
  };
};

export const adminResetPassword = async (userId: string) => {
  const { data } = await api.post(`/users/${userId}/reset-password`);
  return data as {
    user: { id: string; email: string };
    temporary_password: string;
  };
};
