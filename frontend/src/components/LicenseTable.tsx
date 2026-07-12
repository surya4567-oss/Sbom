import type { LicenseItem } from '../types'

interface LicenseTableProps {
  licenses: LicenseItem[]
}

export function LicenseTable({ licenses }: LicenseTableProps) {
  if (!licenses.length) {
    return <p className="text-sm text-slate-500">No license conflicts detected.</p>
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-cyber-700">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-cyber-700 bg-cyber-800/80">
            <th className="px-3 py-2 text-slate-400">Library</th>
            <th className="px-3 py-2 text-slate-400">License</th>
            <th className="px-3 py-2 text-slate-400">Compatibility</th>
            <th className="px-3 py-2 text-slate-400">Conflict Reason</th>
          </tr>
        </thead>
        <tbody>
          {licenses.map((l, i) => (
            <tr key={`${l.license}-${i}`} className="border-b border-cyber-700/50">
              <td className="px-3 py-2 text-slate-300">{l.library || '—'}</td>
              <td className="px-3 py-2 text-slate-300">{l.license}</td>
              <td className="px-3 py-2">
                <span className={l.compatibility === 'Compatible' ? 'text-risk-safe' : 'text-risk-high'}>
                  {l.compatibility}
                </span>
              </td>
              <td className="px-3 py-2 text-slate-400">{l.conflictReason || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
