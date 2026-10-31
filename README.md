# Threat Hunter Lab

[![Python CI](https://github.com/Mikario22/threat-hunter-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Mikario22/threat-hunter-lab/actions/workflows/ci.yml)

An **offline, explainable defensive threat-hunting engine** built as a personal engineering portfolio project. It consumes strictly validated **synthetic identity events**, correlates behavior over time, and produces evidence-backed findings for human review. No cloud, network, secrets, company logs, or external AI calls are required.

## Problem solved

A single failed authentication doesn't tell a security team much. Correlating events across accounts, sources and time can expose suspicious patterns: password spraying, failures that precede a successful login, unauthorized privilege changes, and chains connecting them.

## Detection rules

| Rule | Correlation logic | ATT&CK mapping | Priority |
|---|---|---|---|
| `POTENTIAL_PASSWORD_SPRAY` | At least 4 distinct accounts have failed logins from the same IP in 10 minutes | [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | High |
| `FAILURE_TO_SUCCESS` | At least 3 failures followed by success for same account and source in 10 minutes | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) (possible) | High |
| `PRIVILEGE_CHANGE_NO_REFERENCE` | Privileged account change succeeded without a recorded change reference | [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) | High |
| `CREDENTIAL_TO_PRIVILEGE_CHAIN` | Failed logins → success → privileged change on same account/IP within 30 minutes | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) + [T1098](https://attack.mitre.org/techniques/T1098/) | Critical |
| `BEHAVIOR_LOGIN_ANOMALY` | Historical per-account baseline + adaptive multiple-signal deviations (opt-in) | [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) (possible) | High |

ATT&CK mapping indicates a **behavioral similarity**, not proof of exploitation, a confirmed breach, a particular adversary, or attribution. A ticket value is **not proof** of authorization. The thresholds are illustrative, not tuned on production telemetry. Every finding includes stable ID, rule, priority, mapped technique, ordered evidence IDs and an analyst-review recommendation.

## Behavioral Threat Detection v2

An optional offline behavioral layer learns from **separate, historical successful
logins**. It never uses evaluation events to train and rejects training events
at or after the declared cutoff. Profiles require at least six successful
logins spanning three distinct UTC dates in the preceding 30 days. Accounts
without sufficient history are **explicitly marked insufficient_history**,
not automatically treated as suspicious.

The baseline is per account, recording historical source IPs, target hosts,
and usual UTC login hours (with a one-hour tolerance). An anomaly needs
multiple independent signals: **new IP**, **unusual UTC hour**, and/or
**new host**. Accounts with one or two historical IPs need two signals;
accounts with at least three historical IPs need all three. This is a
simple *adaptive heuristic*, not machine learning or a calibrated threat
probability. The event's own ticket does not grant an exception.

Run the behavioral example:

```powershell
python -m threat_hunter_lab hunt samples/behavior_evaluation.jsonl --baseline-events samples/behavior_training.jsonl --baseline-cutoff "2026-10-30T00:00:00+02:00" --output findings.json
```

To apply a separately operator-reviewed maintenance exception:

```powershell
python -m threat_hunter_lab hunt samples/behavior_evaluation.jsonl --baseline-events samples/behavior_training.jsonl --baseline-cutoff "2026-10-30T00:00:00+02:00" --approved-windows samples/approved_windows.json --output findings.json
```

With the seven synthetic evaluation events and 17 synthetic training events,
the example produces three behavioral alerts before the policy and two
after applying its single maintenance exception. The full report records
**every behavioral decision**, including below-threshold events, insufficient
history, one-hour duplicate-alert cooldowns, and which external policy ID
suppressed an otherwise reportable anomaly.

**Policy safety boundary:** An exception must match the *exact account,
source IP, host, and timestamp* within a bounded interval of at most 24 hours;
wildcards are rejected. The policy file includes a reviewer and ticket for
traceability, but the program **cannot independently verify that reviewer,
ticket, or authorization**. An operator must validate and protect policy
files outside this prototype. The exception applies **only** to the
`BEHAVIOR_LOGIN_ANOMALY` rule: it cannot disable password-spray, failed-to-
success, privilege-change, or credential-chain detections.

Additional knobs: `--min-baseline-successes`, `--min-baseline-days`,
`--baseline-lookback-days`, and `--cooldown-minutes`. They apply to
synthetic testing; validate thresholds, trusted training periods, and false-
positive consequences before any authorized deployment. Zero results from
sparse data are **not** evidence that the account is safe. The mapped
[T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) technique
describes a possible attack behavior, not a confirmed compromise.


## Run locally

Requires Python 3.11+.

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m threat_hunter_lab hunt samples/synthetic_events.jsonl --output findings.json
```

Or on macOS/Linux:

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m threat_hunter_lab hunt samples/synthetic_events.jsonl --output findings.json
```

The included 11 synthetic events currently produce **four findings**. `findings.json` is excluded from Git. No auto-remediation is performed. Input must be UTF-8 JSON Lines with the required schema. Event IDs and timezones are validated, including duplicate-event protection and parser input limits.

## Security boundaries

- No real log data, passwords, API keys or identifying employee/customer information in this repository.
- Does not connect to Active Directory, Falcon, cloud tenants or production security systems.
- Does not execute commands, block IP addresses, disable accounts or send alerts.
- Read-only engine; reports are triage suggestions, not verified incidents.
- Real production integrations would require authorization, retention controls, deduplication at ingestion, performance testing, analyst review and audited remediation approvals.

## Roadmap

- [x] Explainable offline detection and cross-rule correlation
- [x] ATT&CK-aligned evidence and reproducible synthetic fixtures
- [x] Unit tests and GitHub Actions
- [x] Behavior baselines, adaptive multi-signal thresholds and scoped maintenance suppression
- [ ] Evaluation fixture with precision, recall and false-positive analysis
- [ ] Analyst case-management API and role-based review
- [ ] Read-only integrations to an explicitly authorized environment

This repository demonstrates practical defensive engineering. All ATT&CK mapping links point to MITRE's reference documentation.
