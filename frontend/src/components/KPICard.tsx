import clsx from 'clsx'
import type { LucideIcon } from 'lucide-react'

interface KPICardProps {
  title: string
  value: string | number
  icon: LucideIcon
  trend?: string
  variant?: 'default' | 'critical' | 'warning' | 'success'
}

const variantStyles = {
  default: 'border-cyber-700 bg-cyber-800/50',
  critical: 'border-red-500/30 bg-red-500/5',
  warning: 'border-orange-500/30 bg-orange-500/5',
  success: 'border-green-500/30 bg-green-500/5',
}

const iconStyles = {
  default: 'text-cyber-accent',
  critical: 'text-risk-critical',
  warning: 'text-risk-high',
  success: 'text-risk-safe',
}

export function KPICard({ title, value, icon: Icon, trend, variant = 'default' }: KPICardProps) {
  return (
    <div className={clsx('rounded-xl border p-5 transition-shadow hover:shadow-lg hover:shadow-cyber-accent/5', variantStyles[variant])}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-slate-400">{title}</p>
          <p className="mt-2 text-3xl font-bold text-white">{value}</p>
          {trend && <p className="mt-1 text-xs text-slate-500">{trend}</p>}
        </div>
        <div className={clsx('rounded-lg bg-cyber-900 p-2.5', iconStyles[variant])}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  )
}
