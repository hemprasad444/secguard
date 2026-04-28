import api, { invalidateCache } from './client';

export const getProjects = async (page?: number, pageSize?: number) => {
  const { data } = await api.get('/projects/', {
    params: { page, page_size: pageSize },
  });
  return data;
};

export const getProject = async (id: string) => {
  const { data } = await api.get(`/projects/${id}`);
  return data;
};

export const createProject = async (data: {
  name: string;
  description?: string;
  repository_url?: string;
}) => {
  const response = await api.post('/projects/', data);
  return response.data;
};

export const updateProject = async (
  id: string,
  data: { name?: string; description?: string; repository_url?: string }
) => {
  const response = await api.put(`/projects/${id}`, data);
  return response.data;
};

export const deleteProject = async (id: string) => {
  await api.delete(`/projects/${id}`);
  invalidateCache(/\/projects|\/dashboard/);
};

export const getKubeconfigStatus = async (projectId: string) => {
  const { data } = await api.get(`/projects/${projectId}/kubeconfig/status`);
  return data;
};

export const uploadKubeconfig = async (projectId: string, file: File) => {
  const formData = new FormData();
  formData.append('kubeconfig', file);
  const { data } = await api.put(`/projects/${projectId}/kubeconfig`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return data;
};

export const deleteKubeconfig = async (projectId: string) => {
  await api.delete(`/projects/${projectId}/kubeconfig`);
};

export const configureSonarqube = async (
  projectId: string,
  body: { url: string; project_key: string; token?: string },
) => {
  const { data } = await api.put(`/projects/${projectId}/sonarqube`, body);
  return data;
};

export const removeSonarqube = async (projectId: string) => {
  await api.delete(`/projects/${projectId}/sonarqube`);
};

export const testSonarqube = async (projectId: string) => {
  const { data } = await api.post(`/projects/${projectId}/sonarqube/test`);
  return data as { ok: boolean; detail: string };
};

export const syncSonarqube = async (projectId: string) => {
  const { data } = await api.post(`/projects/${projectId}/sonarqube/sync`);
  return data as { task_id: string; status: string };
};
