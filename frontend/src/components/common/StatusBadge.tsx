interface Props {
  status: string;
}

const COLORS: Record<string, string> = {
  // Finding statuses
  open: 'bg-blue-100 text-blue-800',
  in_progress: 'bg-yellow-100 text-yellow-800',
  resolved: 'bg-green-100 text-green-800',
  false_positive: 'bg-gray-100 text-gray-800',
  accepted: 'bg-gray-100 text-gray-800',

  // Scan statuses
  pending: 'bg-gray-100 text-gray-600',
  running: 'bg-yellow-100 text-yellow-800',
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
};

/** Human-readable labels for status values that use underscores. */
function formatLabel(status: string): string {
  return status.replace(/_/g, ' ');
}

export default function StatusBadge({ status }: Props) {
  const color = COLORS[status] || 'bg-gray-100 text-gray-800';
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${color}`}
    >
      {formatLabel(status)}
    </span>
  );
}
