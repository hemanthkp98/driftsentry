# Continuous Drift Monitoring

## Overview & Architecture

Continuous Drift Monitoring transforms DriftSentry from a simple one-shot audit tool into a persistent "immune system" for your cloud infrastructure. By saving scan results in a durable local database and comparing consecutive scans, DriftSentry detects state transitions over time.

This allows the system to distinguish between a newly drifted resource, a recurring issue that has been ignored for weeks, or a resolved drift that was corrected back to the IaC baseline.

## Durable History Store

By default, DriftSentry saves every scan result to a local SQLite database:
- **Location:** `~/.driftsentry/history.db`
- **Schema:** 
  - `scan_snapshots`: Stores metadata about each scan (timestamp, resource counts).
  - `drift_item_snapshots`: Stores individual drifted resources and their severity for a specific scan.
- **Retention:** Configurable via `retention_days` (default: 90 days). Older scans are automatically pruned when you run `driftsentry history prune`.

## Regression Delta Lifecycle

When history is enabled, DriftSentry classifies each drift item into one of five states by comparing the current scan against the previous one:

- 🆕 **NEW**: Drift appearing for the first time.
- 🔄 **REGRESSION**: Drift on a resource that was previously fixed but has drifted again.
- ✅ **RESOLVED**: Drift that was present previously but is now corrected in the cloud.
- ⏩ **RECURRING**: Drift that persists unchanged across consecutive scans.
- ⚠️ **WORSENED**: Drift where severity has increased (e.g., `MEDIUM` → `CRITICAL`).

## Chronic Offenders

You can identify resources that drift repeatedly by analyzing the history store:

```bash
driftsentry history offenders --min 3
```

This command lists resources that have drifted 3 or more times across your history, helping you identify systemic issues or "break-glass" habits within your team.

## Scheduled Monitoring & Smart Alerting

You can run DriftSentry as a continuous daemon using the `monitor` command:

```bash
driftsentry monitor
```

The monitor loops indefinitely, waiting between scans (minimum 5 minutes). You can gracefully stop it using `SIGINT` (Ctrl+C) or `SIGTERM`. It will finish the current scan and then exit cleanly.

**Smart Alerting:**
When integrated with notifications (like Slack), `driftsentry monitor` suppresses alerts for **RECURRING** drift. You will only be notified when drift is NEW, WORSENED, or a REGRESSION. This prevents alert fatigue caused by repeating the same warnings on every scan loop.

## One-Shot vs. Continuous Modes

- **Persistent Monitoring:** Use `driftsentry monitor` or `driftsentry scan` with `history: enabled: true` (default). This populates the durable store and provides regression intelligence.
- **One-Shot Audit:** Use `driftsentry scan --no-history` for ad-hoc developer checks or stateless CI pull request checks. This skips the history database completely, making the run 100% read-only against your local machine.

## Deployment Patterns

### Systemd Service
```ini
[Unit]
Description=DriftSentry Monitor

[Service]
ExecStart=/usr/local/bin/driftsentry monitor
Restart=always
User=driftsentry
Environment=DRIFTSENTRY_SLACK_WEBHOOK=https://hooks.slack.com/...

[Install]
WantedBy=multi-user.target
```

### Kubernetes CronJob
You can deploy `driftsentry monitor --once` in a CronJob, or run `driftsentry monitor` in a long-lived Deployment (ensure you mount a PersistentVolume to `~/.driftsentry/` if you want to keep history between pod restarts).
