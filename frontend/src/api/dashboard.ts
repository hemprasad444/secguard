import api from './client';

export const getSummary = async (projectId?: string, scanType?: string) => {
  const params: Record<string, string> = {};
  if (projectId) params.project_id = projectId;
  if (scanType)  params.scan_type  = scanType;
  const { data } = await api.get('/dashboard/summary', { params });
  return data;
};

export const getTrends = async (projectId?: string, scanType?: string) => {
  const params: Record<string, string> = {};
  if (projectId) params.project_id = projectId;
  if (scanType)  params.scan_type  = scanType;
  const { data } = await api.get('/dashboard/trends', { params });
  return data;
};

export const getToolBreakdown = async (projectId?: string, scanType?: string) => {
  const params: Record<string, string> = {};
  if (projectId) params.project_id = projectId;
  if (scanType)  params.scan_type  = scanType;
  const { data } = await api.get('/dashboard/tool-breakdown', { params });
  return data;
};

export const getImageBreakdown = async (projectId?: string, scanType?: string) => {
  const params: Record<string, string> = {};
  if (projectId) params.project_id = projectId;
  if (scanType)  params.scan_type  = scanType;
  const { data } = await api.get('/dashboard/image-breakdown', { params });
  return data;
};

export const getProjectsOverview = async (scanType?: string) => {
  const params: Record<string, string> = {};
  if (scanType) params.scan_type = scanType;
  const { data } = await api.get('/dashboard/projects-overview', { params });
  return data;
};

export const getScanTypeSeverity = async (projectId?: string, scanType?: string) => {
  const params: Record<string, string> = {};
  if (projectId) params.project_id = projectId;
  if (scanType)  params.scan_type  = scanType;
  const { data } = await api.get('/dashboard/scan-type-severity', { params });
  return data;
};

export const getCategoryBreakdown = async (projectId?: string, scanType?: string) => {
  const params: Record<string, string> = {};
  if (projectId) params.project_id = projectId;
  if (scanType)  params.scan_type  = scanType;
  const { data } = await api.get('/dashboard/category-breakdown', { params });
  return data;
};

export const getSbomLicenseBreakdown = async (projectId?: string) => {
  const params: Record<string, string> = {};
  if (projectId) params.project_id = projectId;
  const { data } = await api.get('/dashboard/sbom-license-breakdown', { params });
  return data;
};

export const getProjectsSbomOverview = async () => {
  const { data } = await api.get('/dashboard/projects-sbom-overview');
  return data;
};

export const getK8sCategories = async (projectId?: string, toolName?: string) => {
  const params: Record<string, string> = {};
  if (projectId) params.project_id = projectId;
  if (toolName) params.tool_name = toolName;
  const { data } = await api.get('/dashboard/k8s-categories', { params });
  return data;
};

export const getK8sResources = async (projectId?: string, toolName?: string) => {
  const params: Record<string, string> = {};
  if (projectId) params.project_id = projectId;
  if (toolName) params.tool_name = toolName;
  const { data } = await api.get('/dashboard/k8s-resources', { params });
  return data;
};

export const getK8sNamespaces = async (projectId?: string, toolName?: string) => {
  const params: Record<string, string> = {};
  if (projectId) params.project_id = projectId;
  if (toolName) params.tool_name = toolName;
  const { data } = await api.get('/dashboard/k8s-namespaces', { params });
  return data;
};
