// components/AlertList.tsx — Scrollable table of all filtered alerts

import type { Alert, Filters } from '../types'

interface Props {
  alerts: Alert[]
  filters: Filters
  selectedId: string | null
  onSelect: (id: string) => void
}

function severityDot(s: string) {
  const colours: Record<string, string> = {
    HIGH: 'bg-cyber-high',
    MEDIUM: 'bg-cyber-medium',
    LOW: 'bg-cyber-low',
  }
  return <span className={`inline-block w-2 h-2 rounded-full mr-2 ${colours[s] ?? 'bg-cyber-muted'}`} />
}

function formatTs(ts: string) {
  const d = new Date(ts)
  return d.toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'medium' })
}

export function AlertList({ alerts, filters, selectedId, onSelect }: Props) {
  const filtered = alerts.filter((a) => {
    if (filters.severity !== 'ALL' && a.severity !== filters.severity) return false
    if (filters.status !== 'ALL' && a.status !== filters.status) return false
    if (filters.source !== 'ALL' && a.source !== filters.source) return false
    if (filters.search) {
      const q = filters.search.toLowerCase()
      if (
        !a.id.toLowerCase().includes(q) &&
        !a.alert_type.toLowerCase().includes(q) &&
        !a.src_ip.includes(q) &&
        !a.dst_ip.includes(q) &&
        !a.source.toLowerCase().includes(q)
      )
        return false
    }
    return true
  })

  if (filtered.length === 0) {
    return (
      <div className="card p-8 text-center text-cyber-muted">
        No alerts match the current filters.
      </div>
    )
  }

  return (
    <div className="card overflow-hidden">
      <div className="overflow-auto max-h-[calc(100vh-280px)]">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-cyber-surface border-b border-cyber-border z-10">
            <tr>
              <th className="text-left px-3 py-2 text-cyber-muted font-medium text-xs uppercase tracking-wider whitespace-nowrap">ID</th>
              <th className="text-left px-3 py-2 text-cyber-muted font-medium text-xs uppercase tracking-wider whitespace-nowrap hidden lg:table-cell">Source</th>
              <th className="text-left px-3 py-2 text-cyber-muted font-medium text-xs uppercase tracking-wider whitespace-nowrap hidden md:table-cell">Timestamp</th>
              <th className="text-left px-3 py-2 text-cyber-muted font-medium text-xs uppercase tracking-wider whitespace-nowrap">Src IP</th>
              <th className="text-left px-3 py-2 text-cyber-muted font-medium text-xs uppercase tracking-wider whitespace-nowrap hidden sm:table-cell">Dst IP</th>
              <th className="text-left px-3 py-2 text-cyber-muted font-medium text-xs uppercase tracking-wider">Alert Type</th>
              <th className="text-left px-3 py-2 text-cyber-muted font-medium text-xs uppercase tracking-wider whitespace-nowrap">Sev</th>
              <th className="text-left px-3 py-2 text-cyber-muted font-medium text-xs uppercase tracking-wider whitespace-nowrap">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((alert) => (
              <tr
                key={alert.id}
                onClick={() => onSelect(alert.id)}
                className={`
                  border-b border-cyber-border cursor-pointer transition-colors duration-100
                  hover:bg-cyber-border/40
                  ${selectedId === alert.id ? 'bg-cyber-border/60 border-l-2 border-l-cyber-accent' : ''}
                `}
              >
                <td className="px-3 py-2.5 font-mono text-xs text-cyber-accent whitespace-nowrap">{alert.id}</td>
                <td className="px-3 py-2.5 text-cyber-muted text-xs whitespace-nowrap hidden lg:table-cell">{alert.source}</td>
                <td className="px-3 py-2.5 text-cyber-muted text-xs font-mono whitespace-nowrap hidden md:table-cell">{formatTs(alert.timestamp)}</td>
                <td className="px-3 py-2.5 font-mono text-xs whitespace-nowrap">{alert.src_ip}</td>
                <td className="px-3 py-2.5 font-mono text-xs text-cyber-muted whitespace-nowrap hidden sm:table-cell">{alert.dst_ip}</td>
                <td className="px-3 py-2.5 text-xs max-w-[180px]">
                  <span className="truncate block">{alert.alert_type}</span>
                </td>
                <td className="px-3 py-2.5 whitespace-nowrap">
                  <span className={`severity-badge severity-${alert.severity}`}>
                    {severityDot(alert.severity)}{alert.severity}
                  </span>
                </td>
                <td className="px-3 py-2.5 whitespace-nowrap">
                  <span className={`status-badge status-${alert.status}`}>
                    {alert.status === 'in_review' ? 'In Review' : alert.status.charAt(0).toUpperCase() + alert.status.slice(1)}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="px-3 py-2 border-t border-cyber-border text-xs text-cyber-muted">
        Showing {filtered.length} of {alerts.length} alerts
      </div>
    </div>
  )
}
