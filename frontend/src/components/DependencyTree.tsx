import type { DependencyTreeNode } from '../types'
import { ChevronDown, ChevronRight, Package } from 'lucide-react'
import { useState } from 'react'

function TreeNode({ node, depth = 0 }: { node: DependencyTreeNode; depth?: number }) {
  const [expanded, setExpanded] = useState(depth < 2)
  const hasChildren = node.children.length > 0

  return (
    <div style={{ marginLeft: depth * 16 }}>
      <button
        onClick={() => hasChildren && setExpanded(!expanded)}
        className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-cyber-800/50"
      >
        {hasChildren ? (
          expanded ? <ChevronDown className="h-3.5 w-3.5 text-slate-500" /> : <ChevronRight className="h-3.5 w-3.5 text-slate-500" />
        ) : (
          <span className="w-3.5" />
        )}
        <Package className="h-3.5 w-3.5 text-cyber-accent" />
        <span className="text-slate-200">{node.name}</span>
        {node.version && <span className="text-xs text-slate-500">@{node.version}</span>}
        <span className="ml-auto text-xs capitalize text-slate-600">{node.type}</span>
      </button>
      {expanded && hasChildren && (
        <div>
          {node.children.map((child) => (
            <TreeNode key={child.id} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  )
}

interface DependencyTreeProps {
  tree: DependencyTreeNode[]
}

export function DependencyTree({ tree }: DependencyTreeProps) {
  if (!tree.length) {
    return <p className="text-sm text-slate-500">No dependencies found.</p>
  }
  return (
    <div className="rounded-lg border border-cyber-700 bg-cyber-950/50 p-3">
      {tree.map((node) => (
        <TreeNode key={node.id} node={node} />
      ))}
    </div>
  )
}
