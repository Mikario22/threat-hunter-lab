# Threat Hunter Lab

[![Python CI](https://github.com/Mikario22/-threat-hunter-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Mikario22/-threat-hunter-lab/actions/workflows/ci.yml)

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

ATT&CK mapping indicates a **behavioral similarity**, not proof of exploitation, a confirmed breach, a particular adversary, or attribution. A ticket value is **not proof** of authorization. The thresholds are illustrative, not tuned on production telemetry. Every finding includes stable ID, rule, priority, mapped technique, ordered evidence IDs and an analyst-review recommendation.

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
- [ ] Behavior baselines and adaptive thresholds
- [ ] Evaluation fixture with precision, recall and false-positive analysis
- [ ] Analyst case-management API and role-based review
- [ ] Read-only integrations to an explicitly authorized environment

This repository demonstrates practical defensive engineering. All ATT&CK mapping links point to MITRE's reference documentation.
