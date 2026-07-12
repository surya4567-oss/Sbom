import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { FileJson, FileCode, Eye } from 'lucide-react'
import { reportService } from '../services/reportService'
import { ErrorCard, LoadingSkeleton } from '../components/ErrorCard'
import { RiskBadge } from '../components/RiskBadge'
import { downloadBlob } from '../utils'

export function ReportsPage() {
  const [previewHtml, setPreviewHtml] = useState<string | null>(null)

  const { data: report, isLoading, isError, refetch } = useQuery({
    queryKey: ['report', 'all'],
    queryFn: () => reportService.getReport('all'),
  })

  const handleDownloadJson = async () => {
    const data = await reportService.exportJson('all')
    downloadBlob(JSON.stringify(data, null, 2), 'sbom-risk-report.json', 'application/json')
  }

  const handleDownloadHtml = async () => {
    const html = await reportService.exportHtml('all')
    downloadBlob(html, 'sbom-risk-report.html', 'text/html')
  }

  const handlePreviewHtml = async () => {
    const html = await reportService.exportHtml('all')
    setPreviewHtml(html)
  }

  if (isLoading) return <LoadingSkeleton rows={8} />
  if (isError || !report) return <ErrorCard message="Failed to load report." onRetry={() => refetch()} />

  const summary = report['Executive Summary']
  const priorities = report['Remediation Priority'] ?? []

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Reports</h2>
          <p className="mt-1 text-sm text-slate-400">Executive summary and downloadable risk reports</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={handlePreviewHtml}
            className="inline-flex items-center gap-2 rounded-lg border border-cyber-700 bg-cyber-800 px-4 py-2 text-sm text-slate-300 hover:bg-cyber-700"
          >
            <Eye className="h-4 w-4" />
            Preview HTML
          </button>
          <button
            onClick={handleDownloadJson}
            className="inline-flex items-center gap-2 rounded-lg border border-cyber-700 bg-cyber-800 px-4 py-2 text-sm text-slate-300 hover:bg-cyber-700"
          >
            <FileJson className="h-4 w-4" />
            Download JSON
          </button>
          <button
            onClick={handleDownloadHtml}
            className="inline-flex items-center gap-2 rounded-lg bg-cyber-accent px-4 py-2 text-sm font-medium text-cyber-950 hover:bg-cyber-accent-dim"
          >
            <FileCode className="h-4 w-4" />
            Download HTML
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-cyber-accent/20 bg-cyber-accent/5 p-6">
        <h3 className="mb-4 text-lg font-semibold text-white">Executive Summary</h3>
        <p className="text-slate-300">{summary['Executive Summary']}</p>
        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <p className="text-xs font-medium uppercase text-cyber-accent">Key Findings</p>
            <p className="mt-1 text-sm text-slate-400">{summary['Key Findings']}</p>
          </div>
          <div>
            <p className="text-xs font-medium uppercase text-cyber-accent">Top Risks</p>
            <p className="mt-1 text-sm text-slate-400">{summary['Top Risks']}</p>
          </div>
          <div>
            <p className="text-xs font-medium uppercase text-cyber-accent">Business Impact</p>
            <p className="mt-1 text-sm text-slate-400">{summary['Business Impact']}</p>
          </div>
          <div>
            <p className="text-xs font-medium uppercase text-cyber-accent">Immediate Actions</p>
            <p className="mt-1 text-sm text-slate-400">{summary['Immediate Actions']}</p>
          </div>
        </div>
      </div>

      <div>
        <h3 className="mb-4 text-lg font-semibold text-white">Ranked Applications</h3>
        <div className="overflow-x-auto rounded-xl border border-cyber-700">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-cyber-700 bg-cyber-800/80">
                <th className="px-4 py-3 text-slate-400">Rank</th>
                <th className="px-4 py-3 text-slate-400">Application</th>
                <th className="px-4 py-3 text-slate-400">Priority</th>
                <th className="px-4 py-3 text-slate-400">Reason</th>
                <th className="px-4 py-3 text-slate-400">Risk Reduction</th>
                <th className="px-4 py-3 text-slate-400">Fix Effort</th>
              </tr>
            </thead>
            <tbody>
              {priorities.map((p) => (
                <tr key={p.Rank} className="border-b border-cyber-700/50">
                  <td className="px-4 py-3 font-bold text-cyber-accent">#{p.Rank}</td>
                  <td className="px-4 py-3 font-medium text-white">{p.Application}</td>
                  <td className="px-4 py-3"><RiskBadge severity={p.Priority} /></td>
                  <td className="max-w-xs px-4 py-3 text-slate-400">{p.Reason}</td>
                  <td className="px-4 py-3 text-slate-400">{p['Expected Risk Reduction']}</td>
                  <td className="px-4 py-3 text-slate-400">{p['Estimated Fix Effort']}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {previewHtml && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="flex h-[90vh] w-full max-w-5xl flex-col rounded-xl border border-cyber-700 bg-white">
            <div className="flex items-center justify-between border-b px-4 py-3">
              <h4 className="font-semibold text-gray-900">Report Preview</h4>
              <button
                onClick={() => setPreviewHtml(null)}
                className="rounded px-3 py-1 text-sm text-gray-600 hover:bg-gray-100"
              >
                Close
              </button>
            </div>
            <iframe
              srcDoc={previewHtml}
              className="flex-1"
              title="Report Preview"
              sandbox="allow-same-origin"
            />
          </div>
        </div>
      )}
    </div>
  )
}
