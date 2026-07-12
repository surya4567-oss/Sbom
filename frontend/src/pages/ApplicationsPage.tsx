import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Search, Eye } from 'lucide-react'
import { applicationService } from '../services/applicationService'
import { ErrorCard, LoadingSkeleton, EmptyState } from '../components/ErrorCard'
import { RiskBadge } from '../components/RiskBadge'
import { Drawer } from '../components/Drawer'
import { Tabs } from '../components/Tabs'
import { DependencyTree } from '../components/DependencyTree'
import { VulnerabilityTable } from '../components/VulnerabilityTable'
import { LicenseTable } from '../components/LicenseTable'
import { AICard, RemediationCard } from '../components/AICard'
import { formatScore } from '../utils'
import type { ApplicationSummary } from '../types'

function ApplicationDrawer({ appId, onClose }: { appId: string | null; onClose: () => void }) {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['application', appId],
    queryFn: () => applicationService.getApplication(appId!),
    enabled: !!appId,
  })

  return (
    <Drawer
      open={!!appId}
      onClose={onClose}
      title={data?.name ?? 'Application Details'}
      subtitle={data ? `Owner: ${data.riskOverview.businessCriticality} criticality` : undefined}
    >
      {isLoading && <LoadingSkeleton rows={8} />}
      {isError && <ErrorCard message="Failed to load application details." onRetry={() => refetch()} />}
      {data && (
        <Tabs
          tabs={[
            {
              id: 'overview',
              label: 'Risk Overview',
              content: (
                <div className="space-y-4">
                  <div className="grid grid-cols-3 gap-4">
                    <div className="rounded-lg border border-cyber-700 p-4 text-center">
                      <p className="text-xs text-slate-500">Risk Score</p>
                      <p className="mt-1 text-2xl font-bold text-white">{formatScore(data.riskOverview.riskScore)}</p>
                    </div>
                    <div className="rounded-lg border border-cyber-700 p-4 text-center">
                      <p className="text-xs text-slate-500">Severity</p>
                      <div className="mt-2 flex justify-center">
                        <RiskBadge severity={data.riskOverview.severity} />
                      </div>
                    </div>
                    <div className="rounded-lg border border-cyber-700 p-4 text-center">
                      <p className="text-xs text-slate-500">Business Criticality</p>
                      <p className="mt-1 text-lg font-semibold text-white">{data.riskOverview.businessCriticality}</p>
                    </div>
                  </div>
                </div>
              ),
            },
            {
              id: 'deps',
              label: 'Dependencies',
              content: <DependencyTree tree={data.dependencyTree} />,
            },
            {
              id: 'vulns',
              label: 'Vulnerabilities',
              content: <VulnerabilityTable vulnerabilities={data.vulnerabilities} />,
            },
            {
              id: 'licenses',
              label: 'Licenses',
              content: <LicenseTable licenses={data.licenses} />,
            },
            {
              id: 'maintenance',
              label: 'Maintenance',
              content: (
                <div className="overflow-x-auto rounded-lg border border-cyber-700">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="border-b border-cyber-700 bg-cyber-800/80">
                        <th className="px-3 py-2 text-slate-400">Library</th>
                        <th className="px-3 py-2 text-slate-400">Last Updated</th>
                        <th className="px-3 py-2 text-slate-400">Deprecated</th>
                        <th className="px-3 py-2 text-slate-400">Bus Factor</th>
                        <th className="px-3 py-2 text-slate-400">Security Policy</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.maintenance.map((m, i) => (
                        <tr key={i} className="border-b border-cyber-700/50">
                          <td className="px-3 py-2 text-slate-300">{m.library}</td>
                          <td className="px-3 py-2 text-slate-400">{m.lastUpdated}</td>
                          <td className="px-3 py-2">{m.deprecated ? 'Yes' : 'No'}</td>
                          <td className="px-3 py-2 text-slate-400">{m.busFactor}</td>
                          <td className="px-3 py-2 text-slate-400">{m.securityPolicy}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ),
            },
            {
              id: 'ai',
              label: 'AI Analysis',
              content: (
                <div className="space-y-4">
                  <AICard title="AI Risk Explanation" content={data.aiExplanation} />
                  <div>
                    <h4 className="mb-3 font-semibold text-white">AI Remediation</h4>
                    <RemediationCard remediation={data.aiRemediation} />
                  </div>
                </div>
              ),
            },
            {
              id: 'priority',
              label: 'Remediation Priority',
              content: (
                <div className="space-y-3">
                  {data.remediationPriority.map((item) => (
                    <div key={item.rank} className="rounded-lg border border-cyber-700 p-4">
                      <div className="flex items-center gap-3">
                        <span className="flex h-8 w-8 items-center justify-center rounded-full bg-cyber-accent/10 text-sm font-bold text-cyber-accent">
                          P{item.rank}
                        </span>
                        <div>
                          <p className="font-medium text-white">{item.title}</p>
                          <p className="text-sm text-slate-400">{item.description}</p>
                        </div>
                        <RiskBadge severity={item.priority} className="ml-auto" />
                      </div>
                    </div>
                  ))}
                </div>
              ),
            },
          ]}
        />
      )}
    </Drawer>
  )
}

export function ApplicationsPage() {
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['applications'],
    queryFn: applicationService.getApplications,
  })

  const filtered = (data ?? []).filter(
    (app) =>
      app.name.toLowerCase().includes(search.toLowerCase()) ||
      app.owner.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Applications</h2>
        <p className="mt-1 text-sm text-slate-400">Browse and inspect analyzed applications</p>
      </div>

      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
        <input
          type="text"
          placeholder="Search by name or owner..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full rounded-lg border border-cyber-700 bg-cyber-800 py-2.5 pl-10 pr-4 text-sm text-white placeholder-slate-500 focus:border-cyber-accent focus:outline-none"
        />
      </div>

      {isLoading && <LoadingSkeleton rows={8} />}
      {isError && <ErrorCard message="Failed to load applications." onRetry={() => refetch()} />}
      {!isLoading && !isError && filtered.length === 0 && (
        <EmptyState title="No applications found" description="Upload an SBOM to get started." />
      )}

      {!isLoading && !isError && filtered.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-cyber-700">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-cyber-700 bg-cyber-800/80">
                <th className="px-4 py-3 text-slate-400">Application</th>
                <th className="px-4 py-3 text-slate-400">Owner</th>
                <th className="px-4 py-3 text-slate-400">Risk Score</th>
                <th className="px-4 py-3 text-slate-400">Severity</th>
                <th className="px-4 py-3 text-slate-400">Dependencies</th>
                <th className="px-4 py-3 text-slate-400">Status</th>
                <th className="px-4 py-3 text-slate-400">Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((app: ApplicationSummary) => (
                <tr key={app.id} className="border-b border-cyber-700/50 hover:bg-cyber-800/30">
                  <td className="px-4 py-3 font-medium text-white">{app.name}</td>
                  <td className="px-4 py-3 text-slate-400">{app.owner}</td>
                  <td className="px-4 py-3 text-slate-300">{formatScore(app.riskScore)}</td>
                  <td className="px-4 py-3"><RiskBadge severity={app.severity} /></td>
                  <td className="px-4 py-3 text-slate-400">{app.dependencies}</td>
                  <td className="px-4 py-3 text-risk-safe">{app.status}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => setSelectedId(app.id)}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-cyber-accent/10 px-3 py-1.5 text-xs font-medium text-cyber-accent hover:bg-cyber-accent/20"
                    >
                      <Eye className="h-3.5 w-3.5" />
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ApplicationDrawer appId={selectedId} onClose={() => setSelectedId(null)} />
    </div>
  )
}
