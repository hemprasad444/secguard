import React from 'react';

export interface Column<T> {
  key: string;
  header: string;
  render?: (item: T) => React.ReactNode;
}

interface Props<T> {
  columns: Column<T>[];
  data: T[];
  loading?: boolean;
  onRowClick?: (item: T) => void;
}

/** Number of skeleton rows to display while loading. */
const SKELETON_ROWS = 5;

export default function DataTable<T extends Record<string, unknown>>({
  columns,
  data,
  loading = false,
  onRowClick,
}: Props<T>) {
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white shadow-sm">
      <table className="min-w-full divide-y divide-gray-200">
        {/* ---- Head ---- */}
        <thead className="bg-gray-50">
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500"
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>

        {/* ---- Body ---- */}
        <tbody className="divide-y divide-gray-200">
          {loading
            ? /* Skeleton loader rows */
              Array.from({ length: SKELETON_ROWS }).map((_, rowIdx) => (
                <tr key={`skeleton-${rowIdx}`}>
                  {columns.map((col) => (
                    <td key={col.key} className="px-6 py-4">
                      <div className="h-4 w-3/4 animate-pulse rounded bg-gray-200" />
                    </td>
                  ))}
                </tr>
              ))
            : data.length === 0
              ? /* Empty state */
                <tr>
                  <td
                    colSpan={columns.length}
                    className="px-6 py-12 text-center text-sm text-gray-500"
                  >
                    No data available.
                  </td>
                </tr>
              : /* Data rows */
                data.map((item, rowIdx) => (
                  <tr
                    key={(item.id as string | number) ?? rowIdx}
                    onClick={() => onRowClick?.(item)}
                    className={`transition-colors ${
                      onRowClick
                        ? 'cursor-pointer hover:bg-gray-50'
                        : ''
                    }`}
                  >
                    {columns.map((col) => (
                      <td
                        key={col.key}
                        className="whitespace-nowrap px-6 py-4 text-sm text-gray-700"
                      >
                        {col.render
                          ? col.render(item)
                          : (item[col.key] as React.ReactNode) ?? '—'}
                      </td>
                    ))}
                  </tr>
                ))}
        </tbody>
      </table>
    </div>
  );
}
