import api from './client';

export const uploadReport = async (
  file: File,
  projectId: string,
  toolName?: string
) => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('project_id', projectId);
  if (toolName) {
    formData.append('tool_name', toolName);
  }
  const { data } = await api.post('/reports/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return data;
};

export const getReports = async (params?: {
  project_id?: string;
  page?: number;
  page_size?: number;
}) => {
  const { data } = await api.get('/reports/', { params });
  return data;
};

export const getReport = async (id: string) => {
  const { data } = await api.get(`/reports/${id}`);
  return data;
};
