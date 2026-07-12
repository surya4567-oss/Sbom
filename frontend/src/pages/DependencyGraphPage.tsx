import { useQuery } from '@tanstack/react-query'
import { useCallback, useMemo, useState } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { applicationService } from '../services/applicationService'
import { graphService } from '../services/graphService'
import { ErrorCard, LoadingSkeleton, EmptyState } from '../components/ErrorCard'
import { getRiskLevelColor } from '../utils'

function CustomNode({ data }: { data: Record<string, unknown> }) {
  const riskLevel = String(data.riskLevel ?? 'safe')
  const color = getRiskLevelColor(riskLevel)
  const nodeType = String(data.nodeType ?? '')

  return (
    <div
      className="rounded-lg border-2 px-3 py-2 shadow-lg"
      style={{ borderColor: color, background: '#151d2e', minWidth: 120 }}
    >
      <p className="text-xs font-bold uppercase" style={{ color }}>
        {nodeType}
      </p>
      <p className="text-sm font-medium text-white">{String(data.label)}</p>
      {data.version ? <p className="text-xs text-slate-500">v{String(data.version)}</p> : null}
    </div>
  )
}

const nodeTypes = { default: CustomNode }

export function DependencyGraphPage() {
  const [selectedAppId, setSelectedAppId] = useState<string>('')
  const [filters, setFilters] = useState({
    showVulnerabilities: true,
    showLicenseConflicts: true,
    showMaintenanceRisks: true,
  })
  const [selectedNode, setSelectedNode] = useState<Record<string, unknown> | null>(null)

  const { data: apps, isLoading: appsLoading } = useQuery({
    queryKey: ['applications'],
    queryFn: applicationService.getApplications,
  })

  const effectiveAppId = selectedAppId || apps?.[0]?.id || ''

  const { data: graphData, isLoading: graphLoading, isError, refetch } = useQuery({
    queryKey: ['graph', effectiveAppId, filters],
    queryFn: () => graphService.getGraph(effectiveAppId, filters),
    enabled: !!effectiveAppId,
  })

  const initialNodes: Node[] = useMemo(
    () =>
      (graphData?.nodes ?? []).map((n) => ({
        id: n.id,
        type: 'default',
        position: n.position,
        data: n.data as unknown as Record<string, unknown>,
      })),
    [graphData],
  )

  const initialEdges: Edge[] = useMemo(
    () =>
      (graphData?.edges ?? []).map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        animated: e.animated,
        style: { stroke: '#334155' },
      })),
    [graphData],
  )

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)

  useMemo(() => {
    setNodes(initialNodes)
    setEdges(initialEdges)
  }, [initialNodes, initialEdges, setNodes, setEdges])

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNode(node.data as Record<string, unknown>)
  }, [])

  if (appsLoading) return <LoadingSkeleton rows={6} />

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Dependency Graph</h2>
        <p className="mt-1 text-sm text-slate-400">Interactive visualization of application dependency chains</p>
      </div>

      <div className="flex flex-wrap items-center gap-4">
        <select
          value={effectiveAppId}
          onChange={(e) => { setSelectedAppId(e.target.value); setSelectedNode(null) }}
          className="rounded-lg border border-cyber-700 bg-cyber-800 px-4 py-2 text-sm text-white focus:border-cyber-accent focus:outline-none"
        >
          {(apps ?? []).map((app) => (
            <option key={app.id} value={app.id}>{app.name}</option>
          ))}
        </select>

        {(['showVulnerabilities', 'showLicenseConflicts', 'showMaintenanceRisks'] as const).map((key) => (
          <label key={key} className="flex items-center gap-2 text-sm text-slate-400">
            <input
              type="checkbox"
              checked={filters[key]}
              onChange={(e) => setFilters((f) => ({ ...f, [key]: e.target.checked }))}
              className="rounded border-cyber-600 bg-cyber-800 text-cyber-accent"
            />
            {key.replace('show', 'Show ').replace(/([A-Z])/g, ' $1').trim()}
          </label>
        ))}

        <div className="ml-auto flex gap-3 text-xs">
          <span className="flex items-center gap-1"><span className="h-3 w-3 rounded-full bg-risk-safe" /> Safe</span>
          <span className="flex items-center gap-1"><span className="h-3 w-3 rounded-full bg-risk-high" /> Warning</span>
          <span className="flex items-center gap-1"><span className="h-3 w-3 rounded-full bg-risk-critical" /> Critical</span>
        </div>
      </div>

      {graphLoading && <LoadingSkeleton rows={4} />}
      {isError && <ErrorCard message="Failed to load dependency graph." onRetry={() => refetch()} />}
      {!graphLoading && !isError && !graphData?.nodes.length && (
        <EmptyState title="No graph data" description="Select an application to view its dependency graph." />
      )}

      {!graphLoading && graphData && graphData.nodes.length > 0 && (
        <div className="flex gap-4">
          <div className="h-[600px] flex-1 rounded-xl border border-cyber-700 bg-cyber-900">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={onNodeClick}
              nodeTypes={nodeTypes}
              fitView
              minZoom={0.2}
            >
              <Background color="#334155" gap={20} />
              <Controls className="!bg-cyber-800 !border-cyber-600 !fill-slate-300" />
              <MiniMap
                nodeColor={(n) => getRiskLevelColor(String((n.data as Record<string, unknown>).riskLevel ?? 'safe'))}
                className="!bg-cyber-800 !border-cyber-600"
              />
            </ReactFlow>
          </div>

          {selectedNode && (
            <div className="w-72 shrink-0 rounded-xl border border-cyber-700 bg-cyber-800/50 p-5">
              <h4 className="mb-4 font-semibold text-white">Node Details</h4>
              <dl className="space-y-3 text-sm">
                <div>
                  <dt className="text-xs text-slate-500">Library Name</dt>
                  <dd className="text-slate-200">{String(selectedNode.libraryName ?? selectedNode.label)}</dd>
                </div>
                {selectedNode.version ? (
                  <div>
                    <dt className="text-xs text-slate-500">Version</dt>
                    <dd className="text-slate-200">{String(selectedNode.version)}</dd>
                  </div>
                ) : null}
                <div>
                  <dt className="text-xs text-slate-500">CVEs</dt>
                  <dd className="text-slate-200">
                    {(selectedNode.cves as string[])?.length
                      ? (selectedNode.cves as string[]).join(', ')
                      : 'None'}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-slate-500">License</dt>
                  <dd className="text-slate-200">{String(selectedNode.license || 'N/A')}</dd>
                </div>
                <div>
                  <dt className="text-xs text-slate-500">Maintenance Status</dt>
                  <dd className="text-slate-200">{String(selectedNode.maintenanceStatus ?? 'Unknown')}</dd>
                </div>
              </dl>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
