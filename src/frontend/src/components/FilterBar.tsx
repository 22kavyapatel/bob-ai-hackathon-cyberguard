// components/FilterBar.tsx — Severity, source, status and text search filters

import type { Alert, Filters } from '../types'

interface Props {
  filters: Filters
  alerts: Alert[]
  onChange: (f: Filters) => void
}

export function FilterBar({ filters, alerts, onChange }: Props) {
  const sources = Array.from(new Set(alerts.map((a) => a.source))).sort()

  return (
    <div className="flex flex-wrap gap-2 items-center">
      {/* Search */}
      <input
        type="text"
        placeholder="Search alerts…"
        value={filters.search}
        onChange={(e) => onChange({ ...filters, search: e.target.value })}
        className="input-search max-w-xs"
      />

      {/* Severity */}
      <select
        value={filters.severity}
        onChange={(e) => onChange({ ...filters, severity: e.target.value as Filters['severity'] })}
        className="filter-select"
      >
        <option value="ALL">All Severities</option>
        <option value="HIGH">HIGH</option>
        <option value="MEDIUM">MEDIUM</option>
        <option value="LOW">LOW</option>
      </select>

      {/* Source */}
      <select
        value={filters.source}
        onChange={(e) => onChange({ ...filters, source: e.target.value })}
        className="filter-select"
      >
        <option value="ALL">All Sources</option>
        {sources.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>

      {/* Status */}
      <select
        value={filters.status}
        onChange={(e) => onChange({ ...filters, status: e.target.value as Filters['status'] })}
        className="filter-select"
      >
        <option value="ALL">All Statuses</option>
        <option value="open">Open</option>
        <option value="in_review">In Review</option>
        <option value="closed">Closed</option>
      </select>

      {/* Clear */}
      {(filters.severity !== 'ALL' || filters.status !== 'ALL' || filters.source !== 'ALL' || filters.search) && (
        <button
          onClick={() => onChange({ severity: 'ALL', status: 'ALL', source: 'ALL', search: '' })}
          className="btn-ghost text-xs"
        >
          Clear filters
        </button>
      )}
    </div>
  )
}
