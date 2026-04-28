import { useState } from 'react';
import { Shield, Server, Package, Lock, FileText, GitCompare } from 'lucide-react';

interface DashboardTab {
  key: string;
  uid: string;
  label: string;
  icon: React.ElementType;
  color: string;
}

const DASHBOARDS: DashboardTab[] = [
  { key: 'dependency', uid: 'opensentinel-dependency', label: 'Dependency', icon: Package,     color: '#0891b2' },
  { key: 'secrets',    uid: 'opensentinel-secrets',    label: 'Secrets',    icon: Lock,        color: '#dc2626' },
  { key: 'sbom',       uid: 'opensentinel-sbom',       label: 'SBOM',       icon: FileText,    color: '#7c3aed' },
  { key: 'k8s',        uid: 'opensentinel-k8s',        label: 'K8s',        icon: Server,      color: '#059669' },
  { key: 'compare',    uid: 'opensentinel-compare',    label: 'Compare',    icon: GitCompare,  color: '#6366f1' },
];

export default function Dashboards() {
  const [active, setActive] = useState(DASHBOARDS[0]);
  const grafanaHost = typeof window !== 'undefined'
    ? `${window.location.protocol}//${window.location.hostname}:3000`
    : '';
  // kiosk mode: fully hide Grafana chrome (sidebar, topnav) - variables still show within dashboard
  const iframeSrc = `${grafanaHost}/d/${active.uid}?orgId=1&theme=light&refresh=30s&kiosk`;

  return (
    <div className="flex h-[calc(100vh-4rem)] flex-col">
      <div className="border-b border-gray-200 mb-3">
        <div className="flex items-center justify-between pb-2">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-gray-700" />
            <h1 className="text-lg font-semibold text-gray-900">Security Analytics</h1>
          </div>
        </div>
        <div className="flex items-center gap-4 overflow-x-auto">
          {DASHBOARDS.map(d => {
            const Ic = d.icon;
            const isActive = active.key === d.key;
            return (
              <button key={d.key} onClick={() => setActive(d)}
                className={`inline-flex items-center gap-2 border-b-2 px-2 py-2 text-sm font-medium transition-colors whitespace-nowrap ${
                  isActive ? 'text-gray-900' : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
                style={isActive ? { borderColor: d.color } : undefined}>
                <Ic className="h-4 w-4" style={{ color: isActive ? d.color : undefined }} />
                {d.label}
              </button>
            );
          })}
        </div>
      </div>

      <div className="flex-1 overflow-hidden rounded border border-gray-200 bg-white">
        <iframe
          key={active.key}
          src={iframeSrc}
          className="w-full h-full border-0"
          title={active.label}
          sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-downloads"
        />
      </div>
    </div>
  );
}
