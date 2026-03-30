import { Shield, AlertTriangle, AlertCircle, Bug } from 'lucide-react';

interface SummaryData {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  open_findings: number;
  resolved_findings: number;
  total_scans: number;
  total_projects: number;
}

interface Props {
  data: SummaryData | null;
  loading: boolean;
}

export default function SummaryCards({ data, loading }: Props) {
  const cards = [
    { label: 'Total Findings', value: data?.total_findings || 0, icon: Shield, color: 'bg-blue-500', textColor: 'text-blue-600' },
    { label: 'Critical', value: data?.critical || 0, icon: AlertTriangle, color: 'bg-red-500', textColor: 'text-red-600' },
    { label: 'High', value: data?.high || 0, icon: AlertCircle, color: 'bg-orange-500', textColor: 'text-orange-600' },
    { label: 'Open Issues', value: data?.open_findings || 0, icon: Bug, color: 'bg-yellow-500', textColor: 'text-yellow-600' },
  ];

  if (loading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[1,2,3,4].map(i => (
          <div key={i} className="bg-white rounded-lg shadow p-6 animate-pulse">
            <div className="h-4 bg-gray-200 rounded w-24 mb-3"></div>
            <div className="h-8 bg-gray-200 rounded w-16"></div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {cards.map(card => {
        const Icon = card.icon;
        return (
          <div key={card.label} className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">{card.label}</p>
                <p className={`text-3xl font-bold ${card.textColor}`}>{card.value}</p>
              </div>
              <div className={`${card.color} p-3 rounded-full`}>
                <Icon className="h-6 w-6 text-white" />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
