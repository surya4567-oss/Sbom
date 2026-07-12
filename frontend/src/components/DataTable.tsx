import clsx from 'clsx'
import type { ReactNode } from 'react'

interface DataTableProps<T> {
  columns: { key: string; header: string; render?: (row: T) => ReactNode }[]
  data: T[]
  onRowClick?: (row: T) => void
  keyField: keyof T
}

export function DataTable<T extends Record<string, unknown>>({
  columns,
  data,
  onRowClick,
  keyField,
}: DataTableProps<T>) {
  return (
    <div className="overflow-x-auto rounded-xl border border-cyber-700">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-cyber-700 bg-cyber-800/80">
            {columns.map((col) => (
              <th key={col.key} className="px-4 py-3 font-semibold text-slate-400">
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row) => (
            <tr
              key={String(row[keyField])}
              className={clsx(
                'border-b border-cyber-700/50 transition-colors',
                onRowClick && 'cursor-pointer hover:bg-cyber-800/50',
              )}
              onClick={() => onRowClick?.(row)}
            >
              {columns.map((col) => (
                <td key={col.key} className="px-4 py-3 text-slate-300">
                  {col.render ? col.render(row) : String(row[col.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
