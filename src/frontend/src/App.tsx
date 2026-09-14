// App.tsx — ThreatSense AI main application

import { useEffect, useState, useCallback } from 'react'
import { api } from './api'
import type { Alert, AlertStatus, Filters, Stats } from './types'
import { StatsBar } from './components/StatsBar'
import { FilterBar } from './components/FilterBar'
import { AlertList } from './components/AlertList'
import { AlertDetail } from './components/AlertDetail'

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [loadingAlerts, setLoadingAlerts] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filters, setFilters] = useState<Filters>({
    severity: 'ALL',
    status: 'ALL',
    source: 'ALL',
    search: '',
  })

  const loadData = useCallback(async () => {
    setLoadingAlerts(true)
    setError(null)
    try {
      const [alertData, statsData] = await Promise.all([api.getAlerts(), api.getStats()])
      setAlerts(alertData)
      setStats(statsData)
    } catch (e) {
      setError(
        e instanceof Error
          ? `Cannot connect to backend: ${e.message}`
          : 'Cannot connect to backend'
      )
    } finally {
      setLoadingAlerts(false)
    }
  }, [])

  useEffect(() => {
    loadData()
  }, [loadData])

  const handleStatusChange = (id: string, status: AlertStatus) => {
    setAlerts((prev) => {
      const updated = prev.map((a) => (a.id === id ? { ...a, status } : a))
      // Recompute stats from the updated list
      setStats((s) =>
        s
          ? {
              ...s,
              open: updated.filter((a) => a.status === 'open').length,
              in_review: updated.filter((a) => a.status === 'in_review').length,
              closed: updated.filter((a) => a.status === 'closed').length,
            }
          : s
      )
      return updated
    })
  }

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-cyber-border bg-cyber-surface/80 backdrop-blur-sm sticky top-0 z-20">
        <div className="max-w-[1600px] mx-auto px-4 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-cyber-accent2/20 border border-cyber-accent2/40 flex items-center justify-center text-cyber-accent text-sm font-bold">
              TS
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-wide text-cyber-text">ThreatSense AI</h1>
              <p className="text-xs text-cyber-muted">Threat Intelligence & Alert Prioritisation</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-cyber-muted hidden sm:block">IBM Bob AI Hackathon 2026 · D2</span>
            <div className="w-2 h-2 rounded-full bg-cyber-low animate-pulse" title="Connected" />
            <button onClick={loadData} className="btn-ghost text-xs" disabled={loadingAlerts}>
              {loadingAlerts ? 'Loading…' : 'Refresh'}
            </button>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="flex-1 max-w-[1600px] mx-auto w-full px-4 py-4 space-y-4">
        {/* Error banner */}
        {error && (
          <div className="bg-red-950 border border-red-800 text-red-300 text-sm rounded px-4 py-3 flex items-center gap-2">
            <span className="text-red-400">⚠</span>
            {error}
            <button onClick={loadData} className="ml-auto text-xs underline hover:no-underline">
              Retry
            </button>
          </div>
        )}

        {/* Stats */}
        <StatsBar stats={stats} loading={loadingAlerts} />

        {/* Filters */}
        <FilterBar filters={filters} alerts={alerts} onChange={setFilters} />

        {/* Two-column layout: list + detail */}
        <div className="flex gap-4 items-start">
          {/* Alert list */}
          <div className="flex-1 min-w-0">
            <AlertList
              alerts={alerts}
              filters={filters}
              selectedId={selectedId}
              onSelect={setSelectedId}
            />
          </div>

          {/* Detail panel */}
          <div className="w-[420px] shrink-0 hidden xl:block">
            <AlertDetail alertId={selectedId} onStatusChange={handleStatusChange} />
          </div>
        </div>

        {/* Mobile: detail shown below list when selected */}
        {selectedId && (
          <div className="xl:hidden">
            <AlertDetail alertId={selectedId} onStatusChange={handleStatusChange} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-cyber-border py-2 px-4">
        <p className="text-xs text-cyber-muted text-center">
          ThreatSense AI · IBM Bob AI Innovation Hackathon 2026 · Problem D2 · All alert data is simulated
        </p>
      </footer>
    </div>
  )
}
