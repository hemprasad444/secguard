import { useState } from 'react';
import { BarChart3, Shield, Server, Package } from 'lucide-react';

const DASHBOARDS = [
  { key: 'overview', uid: 'secguard-overview', label: 'Overview', icon: BarChart3 },
  { key: 'k8s', uid: 'secguard-k8s', label: 'K8s Posture', icon: Server },
  { key: 'images', uid: 'secguard-images', label: 'Images', icon: Package },
];

export default function Dashboards() {
  const [active, setActive] = useState(DASHBOARDS[0]);
  const iframeSrc = `/grafana/d/${active.uid}?orgId=1&kiosk&theme=light`;

  return (
    <div className="flex h-[calc(100vh-4rem)] flex-col">
      {/* Tab bar */}
      <div className="flex items-center gap-4 border-b border-gray-200 pb-3 mb-3">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-gray-700" />
          <h1 className="text-lg font-semibold text-gray-900">Security Analytics</h1>
          <span className="text-[10px] text-gray-400 font-mono uppercase tracking-wider ml-2">powered by grafana</span>
        </div>
        <div className="ml-auto flex items-center gap-4">
          {DASHBOARDS.map(d => {
            const Ic = d.icon;
            const isActive = active.key === d.key;
            return (
              <button key={d.key} onClick={() => setActive(d)}
                className={`inline-flex items-center gap-2 border-b-2 px-2 py-2 text-sm font-medium transition-colors ${
                  isActive ? 'border-gray-900 text-gray-900' : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}>
                <Ic className="h-4 w-4" />
                {d.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Grafana iframe */}
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
