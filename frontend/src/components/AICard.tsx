import { Brain } from 'lucide-react'

interface AICardProps {
  title: string
  content: Record<string, string>
}

export function AICard({ title, content }: AICardProps) {
  const entries = Object.entries(content)

  return (
    <div className="rounded-xl border border-cyber-accent/20 bg-cyber-accent/5 p-5">
      <div className="mb-4 flex items-center gap-2">
        <Brain className="h-5 w-5 text-cyber-accent" />
        <h4 className="font-semibold text-white">{title}</h4>
      </div>
      <div className="space-y-3">
        {entries.map(([key, value]) => (
          <div key={key}>
            <p className="text-xs font-medium uppercase tracking-wider text-cyber-accent">{key}</p>
            <p className="mt-1 text-sm text-slate-300">{value}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

interface RemediationCardProps {
  remediation: {
    'Immediate Actions'?: Array<Record<string, string>>
    'Medium-Term Improvements'?: Array<Record<string, string>>
    'Long-Term Recommendations'?: Array<Record<string, string>>
  }
}

export function RemediationCard({ remediation }: RemediationCardProps) {
  const sections = [
    { title: 'Immediate Actions', items: remediation['Immediate Actions'] ?? [] },
    { title: 'Medium-Term Improvements', items: remediation['Medium-Term Improvements'] ?? [] },
    { title: 'Long-Term Recommendations', items: remediation['Long-Term Recommendations'] ?? [] },
  ]

  return (
    <div className="space-y-4">
      {sections.map((section) =>
        section.items.length > 0 ? (
          <div key={section.title} className="rounded-lg border border-cyber-700 p-4">
            <h5 className="mb-3 text-sm font-semibold text-white">{section.title}</h5>
            {section.items.map((item, i) => (
              <div key={i} className="mb-3 last:mb-0">
                <p className="font-medium text-cyber-accent">{item.What}</p>
                <p className="mt-1 text-sm text-slate-400">{item.Why}</p>
                <p className="mt-1 text-xs text-slate-500">How: {item.How}</p>
              </div>
            ))}
          </div>
        ) : null,
      )}
    </div>
  )
}
