interface Props {
  severity: string;
}

const COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-blue-100 text-blue-800',
  info: 'bg-gray-100 text-gray-800',
};

export default function SeverityBadge({ severity }: Props) {
  const color = COLORS[severity] || COLORS.info;
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${color}`}
    >
      {severity}
    </span>
  );
}
