import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';

interface DashboardSummary {
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
  data: DashboardSummary | null;
  loading: boolean;
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#d97706',
  Low: '#2563eb',
  Info: '#6b7280',
};

export default function SeverityChart({ data, loading }: Props) {
  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="h-4 bg-gray-200 rounded w-48 mb-6 animate-pulse"></div>
        <div className="h-64 bg-gray-100 rounded animate-pulse"></div>
      </div>
    );
  }

  const chartData = data
    ? [
        { name: 'Critical', value: data.critical },
        { name: 'High', value: data.high },
        { name: 'Medium', value: data.medium },
        { name: 'Low', value: data.low },
        { name: 'Info', value: data.info },
      ].filter(entry => entry.value > 0)
    : [];

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold text-gray-800 mb-4">Severity Distribution</h3>
      {chartData.length === 0 ? (
        <div className="h-64 flex items-center justify-center text-gray-400">
          No severity data available
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={100}
              paddingAngle={3}
              dataKey="value"
              label={({ name, percent }) =>
                `${name} ${(percent * 100).toFixed(0)}%`
              }
            >
              {chartData.map((entry) => (
                <Cell
                  key={`cell-${entry.name}`}
                  fill={SEVERITY_COLORS[entry.name]}
                />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
