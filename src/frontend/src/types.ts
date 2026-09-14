// Shared TypeScript types for ThreatSense AI frontend

export type Severity = 'HIGH' | 'MEDIUM' | 'LOW'
export type AlertStatus = 'open' | 'in_review' | 'closed'
export type Classification =
  | 'Likely Threat'
  | 'Likely False Positive'
  | 'Needs Investigation'

export interface Alert {
  id: string
  source: string
  timestamp: string
  src_ip: string
  dst_ip: string
  alert_type: string
  severity: Severity
  status: AlertStatus
  description: string
}

export interface MitreTechnique {
  id: string
  name: string
  tactic: string
}

export interface AlertAnalysis {
  alert: Alert
  risk_score: number
  classification: Classification
  mitre_techniques: MitreTechnique[]
  recommendations: string[]
  bluf_summary: string
  correlated_alerts: Alert[]
}

export interface Stats {
  total: number
  high: number
  medium: number
  low: number
  open: number
  in_review: number
  closed: number
}

export interface Filters {
  severity: Severity | 'ALL'
  status: AlertStatus | 'ALL'
  source: string | 'ALL'
  search: string
}
