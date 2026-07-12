import clsx from 'clsx'
import type { ReactNode } from 'react'

interface ChartCardProps {
  title: string
  children: ReactNode
  className?: string
}

export function ChartCard({ title, children, className }: ChartCardProps) {
  return (
    <div className={clsx('rounded-xl border border-cyber-700 bg-cyber-800/50 p-5', className)}>
      <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-400">{title}</h3>
      {children}
    </div>
  )
}
