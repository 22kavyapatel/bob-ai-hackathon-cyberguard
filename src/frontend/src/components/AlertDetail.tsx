// components/AlertDetail.tsx — Full analysis panel for a selected alert

import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import type { AlertAnalysis, AlertStatus } from '../types'
import { RiskGauge } from './RiskGauge'

interface Props {
  alertId: string | null
  onStatusChange: (id: string, status: AlertStatus) => void
}

function formatTs(ts: string) {
  const d = new Date(ts)
  return d.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'medium' })
}

function ClassificationBadge({ c }: { c: string }) {
  const styles: Record<string, string> = {
    'Likely Threat': 'bg-red-950 text-red-300 border border-red-700',
    'Needs Investigation': 'bg-amber-950 text-amber-300 border border-amber-700',
    'Likely False Positive': 'bg-slate-800 text-slate-300 border border-slate-600',
  }
  return (
    <span className={`px-3 py-1 rounded-full text-sm font-semibold ${styles[c] ?? ''}`}>
      {c}
    </span>
  )
}

const STATUS_TRANSITIONS: Record<AlertStatus, AlertStatus | null> = {
  open: 'in_review',
  in_review: 'closed',
  closed: null,
}

const STATUS_LABELS: Record<AlertStatus, string> = {
  open: 'Open',
  in_review: 'In Review',
  closed: 'Closed',
}

export function AlertDetail({ alertId, onStatusChange }: Props) {
  const [analysis, setAnalysis] = useState<AlertAnalysis | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [updating, setUpdating] = useState(false)

  const load = useCallback(async (id: string) => {
    setLoading(true)
    setError(null)
    try {
      const data = await api.getAnalysis(id)
      setAnalysis(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load analysis')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (alertId) load(alertId)
    else setAnalysis(null)
  }, [alertId, load])

  const handleStatusUpdate = async (status: AlertStatus) => {
    if (!analysis) return
    setUpdating(true)
    try {
      await api.updateStatus(analysis.alert.id, status)
      onStatusChange(analysis.alert.id, status)
      // Refresh analysis to reflect new status
      await load(analysis.alert.id)
    } finally {
      setUpdating(false)
    }
  }

  if (!alertId) {
    return (
      <div className="card flex-1 flex items-center justify-center min-h-[400px] text-cyber-muted">
        <div className="text-center">
          <div className="text-4xl mb-3 opacity-20">⚡</div>
          <p className="text-sm">Select an alert to see detailed analysis</p>
        </div>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="card flex-1 p-6 space-y-4 animate-pulse">
        <div className="h-4 bg-cyber-border rounded w-2/3" />
        <div className="h-20 bg-cyber-border rounded" />
        <div className="h-4 bg-cyber-border rounded w-1/2" />
        <div className="h-32 bg-cyber-border rounded" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="card flex-1 p-6 text-cyber-high text-sm">
        Error: {error}
      </div>
    )
  }

  if (!analysis) return null

  const { alert, risk_score, classification, mitre_techniques, recommendations, bluf_summary, correlated_alerts } = analysis
  const nextStatus = STATUS_TRANSITIONS[alert.status]

  return (
    <div className="card flex-1 overflow-auto max-h-[calc(100vh-180px)]">
      {/* Header */}
      <div className="px-4 py-3 border-b border-cyber-border flex items-start justify-between gap-3 flex-wrap">
        <div>
          <p className="font-mono text-xs text-cyber-muted mb-0.5">{alert.id} · {alert.source}</p>
          <h2 className="text-sm font-semibold text-cyber-text">{alert.alert_type}</h2>
          <p className="text-xs text-cyber-muted mt-0.5">{formatTs(alert.timestamp)}</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`severity-badge severity-${alert.severity}`}>{alert.severity}</span>
          <span className={`status-badge status-${alert.status}`}>
            {STATUS_LABELS[alert.status]}
          </span>
          {nextStatus && (
            <button
              onClick={() => handleStatusUpdate(nextStatus)}
              disabled={updating}
              className="btn-primary text-xs"
            >
              {updating ? '…' : `Mark as ${STATUS_LABELS[nextStatus]}`}
            </button>
          )}
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Risk score + classification */}
        <div className="flex items-center gap-6 flex-wrap">
          <RiskGauge score={risk_score} />
          <div>
            <p className="text-xs text-cyber-muted mb-1">Classification</p>
            <ClassificationBadge c={classification} />
          </div>
        </div>

        {/* Connection info */}
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div className="card p-3">
            <p className="text-xs text-cyber-muted mb-0.5">Source IP</p>
            <p className="font-mono text-cyber-accent">{alert.src_ip}</p>
          </div>
          <div className="card p-3">
            <p className="text-xs text-cyber-muted mb-0.5">Destination IP</p>
            <p className="font-mono text-cyber-accent">{alert.dst_ip}</p>
          </div>
        </div>

        {/* BLUF summary */}
        <div>
          <h3 className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2 flex items-center gap-1">
            <span className="inline-block w-1 h-3 bg-cyber-accent rounded-full" />
            BLUF Threat Summary
          </h3>
          <div className="bg-black/30 border border-cyber-border rounded p-3 text-sm leading-relaxed text-cyber-text">
            {bluf_summary}
          </div>
        </div>

        {/* MITRE ATT&CK */}
        {mitre_techniques.length > 0 && (
          <div>
            <h3 className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2 flex items-center gap-1">
              <span className="inline-block w-1 h-3 bg-amber-400 rounded-full" />
              MITRE ATT&CK Techniques
            </h3>
            <div className="space-y-1.5">
              {mitre_techniques.map((t) => (
                <div key={t.id} className="flex items-start gap-2 text-sm">
                  <a
                    href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/').toUpperCase()}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-cyber-accent hover:underline shrink-0 text-xs mt-0.5"
                  >
                    {t.id}
                  </a>
                  <div>
                    <span className="text-cyber-text">{t.name}</span>
                    <span className="ml-2 text-xs text-cyber-muted">({t.tactic})</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommended Actions */}
        <div>
          <h3 className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2 flex items-center gap-1">
            <span className="inline-block w-1 h-3 bg-cyber-low rounded-full" />
            Recommended Actions
          </h3>
          <ol className="space-y-1.5">
            {recommendations.map((rec, i) => (
              <li key={i} className="flex gap-2 text-sm">
                <span className="text-cyber-muted font-mono text-xs mt-0.5 shrink-0">{String(i + 1).padStart(2, '0')}.</span>
                <span className="text-cyber-text">{rec}</span>
              </li>
            ))}
          </ol>
        </div>

        {/* Correlated Alerts */}
        {correlated_alerts.length > 0 && (
          <div>
            <h3 className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2 flex items-center gap-1">
              <span className="inline-block w-1 h-3 bg-red-400 rounded-full" />
              Correlated Alerts ({correlated_alerts.length})
            </h3>
            <div className="space-y-1.5">
              {correlated_alerts.slice(0, 8).map((ca) => (
                <div key={ca.id} className="flex items-center gap-2 text-xs bg-black/20 rounded px-2 py-1.5 border border-cyber-border">
                  <span className="font-mono text-cyber-muted shrink-0">{ca.id}</span>
                  <span className={`severity-badge severity-${ca.severity} shrink-0`}>{ca.severity}</span>
                  <span className="text-cyber-text truncate">{ca.alert_type}</span>
                  <span className="text-cyber-muted shrink-0 ml-auto font-mono">{ca.src_ip}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Description */}
        <div>
          <h3 className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2">Raw Alert Description</h3>
          <p className="text-xs text-cyber-muted leading-relaxed bg-black/20 border border-cyber-border rounded p-3">
            {alert.description}
          </p>
        </div>
      </div>
    </div>
  )
}
