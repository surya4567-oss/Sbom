import clsx from 'clsx'
import { getSeverityColor } from '../utils'

interface RiskBadgeProps {
  severity: string
  className?: string
}

export function RiskBadge({ severity, className }: RiskBadgeProps) {
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium',
        getSeverityColor(severity),
        className,
      )}
    >
      {severity}
    </span>
  )
}
