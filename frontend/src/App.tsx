import { Routes, Route, Navigate } from 'react-router-dom';
import { useEffect } from 'react';
import Layout from './components/layout/Layout';
import Login from './pages/Login';
import SignUp from './pages/SignUp';
import Dashboards from './pages/Dashboards';
import Projects from './pages/Projects';
import ProjectDetail from './pages/ProjectDetail';
import ScanDetail from './pages/ScanDetail';
import PackageDetail from './pages/PackageDetail';
import ScanTypeDetail from './pages/ScanTypeDetail';
import K8sScanDetail from './pages/K8sScanDetail';
import K8sFindingDetail from './pages/K8sFindingDetail';
import SastFindingDetail from './pages/SastFindingDetail';
import Scans from './pages/Scans';
import Findings from './pages/Findings';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import { useAuthStore } from './stores/authStore';
import { getMe } from './api/auth';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  if (!isAuthenticated) return <Navigate to="/login" />;
  return <>{children}</>;
}

export default function App() {
  const { isAuthenticated, setUser } = useAuthStore();

  useEffect(() => {
    if (isAuthenticated) {
      getMe().then(setUser).catch(() => useAuthStore.getState().logout());
    }
  }, [isAuthenticated]);

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<SignUp />} />
      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route index element={<Dashboards />} />
        <Route path="analytics" element={<Navigate to="/" replace />} />
        <Route path="projects" element={<Projects />} />
        <Route path="projects/:id" element={<ProjectDetail />} />
        <Route path="projects/:projectId/scans/:scanId" element={<ScanDetail />} />
        <Route path="projects/:projectId/scans/:scanId/packages/:pkgKey" element={<PackageDetail />} />
        <Route path="projects/:projectId/scans/:scanId/sast/:findingId" element={<SastFindingDetail />} />
        <Route path="projects/:projectId/scan-types/:typeKey" element={<ScanTypeDetail />} />
        <Route path="projects/:projectId/k8s/:scanId" element={<K8sScanDetail />} />
        <Route path="projects/:projectId/k8s/:scanId/findings/:findingId" element={<K8sFindingDetail />} />
        <Route path="scans" element={<Scans />} />
        <Route path="findings" element={<Findings />} />
        <Route path="reports" element={<Reports />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}
