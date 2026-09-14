// components/StatsBar.tsx — Summary statistics at the top of the dashboard

import type { Stats } from '../types'

interface Props {
  stats: Stats | null
  loading: boolean
}

export function StatsBar({ stats, loading }: Props) {
  if (loading || !stats) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="card p-4 animate-pulse">
            <div className="h-3 bg-cyber-border rounded w-16 mb-2" />
            <div className="h-7 bg-cyber-border rounded w-10" />
          </div>
        ))}
      </div>
    )
  }

  const cards = [
    { label: 'Total Alerts', value: stats.total, color: 'text-cyber-accent' },
    { label: 'HIGH Severity', value: stats.high, color: 'text-cyber-high' },
    { label: 'MEDIUM Severity', value: stats.medium, color: 'text-cyber-medium' },
    { label: 'LOW Severity', value: stats.low, color: 'text-cyber-low' },
    { label: 'Open', value: stats.open, color: 'text-red-400' },
    { label: 'In Review', value: stats.in_review, color: 'text-amber-400' },
    { label: 'Closed', value: stats.closed, color: 'text-slate-400' },
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
      {cards.map((card) => (
        <div key={card.label} className="card p-4">
          <p className="text-xs text-cyber-muted uppercase tracking-wider mb-1">{card.label}</p>
          <p className={`text-2xl font-bold font-mono ${card.color}`}>{card.value}</p>
        </div>
      ))}
    </div>
  )
}
