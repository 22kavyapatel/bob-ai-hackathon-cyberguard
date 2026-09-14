# Problem Statement

## Background

Modern enterprise environments generate tens of thousands of security events per day from firewalls, intrusion detection systems (IDS), endpoint detection and response (EDR) tools, web application firewalls (WAF), and cloud platforms. These raw events are ingested by a Security Information and Event Management (SIEM) system and surfaced as alerts for human analysts in a Security Operations Centre (SOC).

## The Problem

SOC analysts face an overwhelming volume of low-context, isolated security alerts. A typical Tier-1 analyst may receive 300–500 alerts per 8-hour shift, yet industry research shows that over 70% of these alerts are either duplicates, false positives, or low-priority noise. Critical threats — such as an ongoing lateral movement campaign or a credential stuffing attack — appear as dozens of disconnected individual alerts that look unremarkable in isolation.

Without an intelligent correlation and prioritisation layer, analysts must:

1. **Manually review each alert individually** — averaging 3–5 minutes per alert for initial triage.
2. **Mentally correlate patterns** across hundreds of alerts without automated assistance.
3. **Guess at priority** using only severity labels (HIGH / MEDIUM / LOW) set by the alerting rule, which do not account for context, frequency, or related activity.
4. **Write investigation notes** from scratch for every incident, with no AI-generated starting point.

This leads to **alert fatigue**, where analysts become desensitised to alerts, causing genuine high-priority threats to be missed or delayed by hours — directly increasing the blast radius of a breach.

## Who is Affected

**Primary users:** Tier-1 and Tier-2 SOC analysts at mid-to-large enterprises who triage incoming security alerts using a SIEM dashboard.

**Secondary users:** Incident response managers who need rapid situational awareness reports and SOC leads who must prioritise analyst workload.

These analysts typically have strong security knowledge but limited time — they need decisions fast, not another screen full of raw log data.

## Why It Matters

- **Financial impact:** The average cost of a data breach in 2024 was USD 4.88 million (IBM Cost of a Data Breach Report). Faster detection and response directly reduces this cost.
- **Dwell time:** Attackers remain undetected for an average of 194 days in environments without effective alert triage. Every hour of delayed detection increases damage.
- **Analyst burnout:** High false-positive rates are cited as the #1 cause of analyst turnover in SOC teams, creating a talent retention crisis in cybersecurity.

## Why Existing Solutions Fall Short

Current SIEM dashboards display alerts in a flat, reverse-chronological list. Rule-based correlation engines can group events by IP or time window but produce no natural-language explanation, no contextual risk score, and no recommended actions. Analysts still spend the majority of their time on manual triage tasks that could be automated. Existing AI-augmented SIEM products are expensive enterprise platforms — there is no accessible, AI-first tool that a team can deploy quickly for a demo or pilot.
