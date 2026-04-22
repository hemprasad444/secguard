import api, { invalidateCache } from './client';

export const triggerScan = async (data: {
  project_id: string;
  tool_name: string;
  config?: Record<string, string>;
}) => {
  const response = await api.post('/scans/trigger', data);
  invalidateCache(/\/scans|\/dashboard/);
  return response.data;
};

export const triggerImageUploadScan = async (
  projectId: string,
  file: File,
  registryUsername?: string,
  registryPassword?: string,
) => {
  const formData = new FormData();
  formData.append('project_id', projectId);
  formData.append('file', file);
  if (registryUsername) formData.append('registry_username', registryUsername);
  if (registryPassword) formData.append('registry_password', registryPassword);
  const response = await api.post('/scans/trigger-image-upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
};

export const triggerCodeUploadScan = async (
  projectId: string,
  file: File,
) => {
  const formData = new FormData();
  formData.append('project_id', projectId);
  formData.append('file', file);
  const response = await api.post('/scans/trigger-code-upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  invalidateCache(/\/scans|\/dashboard/);
  return response.data;
};

export const getScans = async (params?: {
  project_id?: string;
  tool_name?: string;
  status?: string;
  page?: number;
  page_size?: number;
}) => {
  const { data } = await api.get('/scans/', { params });
  return data;
};

export const getScan = async (id: string) => {
  const { data } = await api.get(`/scans/${id}`);
  return data;
};

export const getScanFindings = async (
  id: string,
  page?: number,
  pageSize?: number
) => {
  const { data } = await api.get(`/scans/${id}/findings`, {
    params: { page, page_size: pageSize },
  });
  return data;
};

export const getScanSbom = async (id: string) => {
  const { data } = await api.get(`/scans/${id}/sbom`);
  return data;
};

export const deleteScan = async (id: string) => {
  await api.delete(`/scans/${id}`);
  invalidateCache(/\/scans|\/dashboard/);
};
