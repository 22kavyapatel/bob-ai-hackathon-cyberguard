// components/RiskGauge.tsx — Circular risk score indicator

interface Props {
  score: number
}

function scoreColor(score: number) {
  if (score >= 80) return '#ef4444'
  if (score >= 60) return '#f97316'
  if (score >= 40) return '#f59e0b'
  return '#22c55e'
}

function scoreLabel(score: number) {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 40) return 'MEDIUM'
  return 'LOW'
}

export function RiskGauge({ score }: Props) {
  const radius = 40
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference
  const color = scoreColor(score)

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="100" height="100" viewBox="0 0 100 100">
        {/* Background circle */}
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke="#1e2d4a"
          strokeWidth="10"
        />
        {/* Score arc */}
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 50 50)"
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
        {/* Score text */}
        <text
          x="50"
          y="50"
          textAnchor="middle"
          dominantBaseline="central"
          fill={color}
          fontSize="20"
          fontWeight="bold"
          fontFamily="JetBrains Mono, monospace"
        >
          {score}
        </text>
      </svg>
      <span className="text-xs font-bold font-mono tracking-widest" style={{ color }}>
        {scoreLabel(score)}
      </span>
    </div>
  )
}
