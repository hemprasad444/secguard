import api from './client';

export const getFindings = async (params?: {
  project_id?: string;
  scan_id?: string;
  severity?: string;
  status?: string;
  tool_name?: string;
  page?: number;
  page_size?: number;
}) => {
  const { data } = await api.get('/findings/', { params });
  return data;
};

export const getFinding = async (id: string) => {
  const { data } = await api.get(`/findings/${id}`);
  return data;
};

export const updateFinding = async (
  id: string,
  data: { status?: string; assigned_to?: string }
) => {
  const response = await api.patch(`/findings/${id}`, data);
  return response.data;
};

export const closeFinding = async (
  id: string,
  data: { status: string; close_reason: string; justification?: string }
) => {
  const response = await api.patch(`/findings/${id}/close`, data);
  return response.data;
};

export const reopenFinding = async (id: string, justification?: string) => {
  const response = await api.patch(`/findings/${id}/reopen`, { justification });
  return response.data;
};

export const generateFix = async (id: string) => {
  const response = await api.post(`/findings/${id}/generate-fix`);
  return response.data;
};

export const verifyK8sFinding = async (id: string) => {
  const response = await api.post(`/findings/${id}/verify`);
  return response.data;
};

export const bulkUpdateFindings = async (data: {
  ids: string[];
  status?: string;
}) => {
  const response = await api.patch('/findings/bulk', data);
  return response.data;
};
