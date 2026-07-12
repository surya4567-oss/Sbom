export function getSeverityColor(severity: string): string {
  const s = severity.toLowerCase()
  if (s === 'critical') return 'text-risk-critical bg-red-500/10 border-red-500/30'
  if (s === 'high') return 'text-risk-high bg-orange-500/10 border-orange-500/30'
  if (s === 'medium') return 'text-risk-medium bg-yellow-500/10 border-yellow-500/30'
  return 'text-risk-low bg-green-500/10 border-green-500/30'
}

export function getRiskLevelColor(level: string): string {
  const l = level.toLowerCase()
  if (l === 'critical') return '#ef4444'
  if (l === 'warning') return '#f97316'
  return '#22c55e'
}

export function downloadBlob(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function formatScore(score: number): string {
  return score.toFixed(1)
}
