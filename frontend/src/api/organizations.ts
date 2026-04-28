import api from './client';

export interface SonarqubeOrgStatus {
  url: string | null;
  token_configured: boolean;
}

export interface SonarqubeProjectListItem {
  key: string;
  name: string;
  last_analysis_date: string | null;
  qualifier: string | null;
  visibility: string | null;
}

export interface SonarqubeProjectList {
  items: SonarqubeProjectListItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface SonarqubeImportResult {
  created: string[];
  skipped: string[];
  failed: { key: string; error: string }[];
  queued_syncs: number;
}

export const getOrgSonarqube = async (): Promise<SonarqubeOrgStatus> => {
  const { data } = await api.get('/organizations/me/sonarqube');
  return data;
};

export const setOrgSonarqube = async (body: { url: string; token?: string }): Promise<SonarqubeOrgStatus> => {
  const { data } = await api.put('/organizations/me/sonarqube', body);
  return data;
};

export const removeOrgSonarqube = async () => {
  await api.delete('/organizations/me/sonarqube');
};

export const testOrgSonarqube = async (): Promise<{ ok: boolean; detail: string }> => {
  const { data } = await api.post('/organizations/me/sonarqube/test');
  return data;
};

export const listSonarqubeProjects = async (params: {
  page?: number;
  page_size?: number;
  q?: string;
} = {}): Promise<SonarqubeProjectList> => {
  const { data } = await api.get('/organizations/me/sonarqube/projects', { params });
  return data;
};

export const importSonarqubeProjects = async (body: {
  projects: { key: string; name: string; description?: string }[];
  sync_immediately?: boolean;
}): Promise<SonarqubeImportResult> => {
  const { data } = await api.post('/organizations/me/sonarqube/import', body);
  return data;
};
