// api.ts — HTTP client for ThreatSense AI backend

import type { Alert, AlertAnalysis, AlertStatus, Stats } from './types'

const BASE = '/api'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, options)
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API ${res.status}: ${text}`)
  }
  return res.json() as Promise<T>
}

export const api = {
  getStats: () => request<Stats>('/stats'),

  getAlerts: () => request<Alert[]>('/alerts'),

  getAnalysis: (alertId: string) =>
    request<AlertAnalysis>(`/alerts/${alertId}/analysis`),

  updateStatus: (alertId: string, status: AlertStatus) =>
    request<Alert>(`/alerts/${alertId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    }),
}
