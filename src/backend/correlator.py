"""
correlator.py — Alert correlation engine for ThreatSense AI.

Groups related alerts based on:
  - Same source IP
  - Same destination IP or /24 subnet overlap
  - Same alert type within a ±60 min time window
"""

from __future__ import annotations

from datetime import datetime, timedelta

from alerts import Alert, get_all_alerts

_TIME_WINDOW = timedelta(minutes=60)


def _parse_ts(ts: str) -> datetime:
    """Parse ISO 8601 timestamp (with or without trailing Z)."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)


def _same_subnet_24(ip_a: str, ip_b: str) -> bool:
    """Return True if both IPs share the same /24 prefix."""
    try:
        return ip_a.rsplit(".", 1)[0] == ip_b.rsplit(".", 1)[0]
    except Exception:
        return False


def correlate(alert: Alert) -> list[Alert]:
    """
    Return a list of alerts (excluding the given alert itself) that are
    related to it by source IP, destination subnet, or alert type + time window.
    """
    all_alerts = get_all_alerts()
    target_ts = _parse_ts(alert.timestamp)
    related: list[Alert] = []

    for candidate in all_alerts:
        if candidate.id == alert.id:
            continue

        candidate_ts = _parse_ts(candidate.timestamp)
        time_diff = abs((candidate_ts - target_ts).total_seconds())
        within_window = time_diff <= _TIME_WINDOW.total_seconds()

        same_src = candidate.src_ip == alert.src_ip
        same_dst_subnet = _same_subnet_24(candidate.dst_ip, alert.dst_ip)
        same_type_timed = (candidate.alert_type == alert.alert_type and within_window)

        if same_src or same_dst_subnet or same_type_timed:
            related.append(candidate)

    # Deduplicate and sort newest first
    seen: set[str] = set()
    deduped: list[Alert] = []
    for a in sorted(related, key=lambda x: x.timestamp, reverse=True):
        if a.id not in seen:
            seen.add(a.id)
            deduped.append(a)

    return deduped
