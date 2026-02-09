# EDR PoC - Endpoint Detection & Response

A macOS Endpoint Detection and Response proof of concept inspired by CrowdStrike Falcon's architecture. Features a lightweight sensor agent collecting real-time telemetry, an unsupervised ML detection engine, behavioral IOA rules mapped to MITRE ATT&CK, and a real-time web dashboard.

Built for **educational and security research purposes**.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                Web Dashboard (Flask + WebSocket)          │
│  Real-time alerts │ Process trees │ ML metrics │ MITRE   │
└──────────────────────────┬──────────────────────────────┘
                           │ REST API + WebSocket
┌──────────────────────────┴──────────────────────────────┐
│                   Detection Engine                       │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐ │
│  │ ML Engine │  │ Behavioral   │  │ Threat Intel      │ │
│  │ -IsoForest│  │ Analysis     │  │ -IOC matching     │ │
│  │ -Autoencdr│  │ -17 IOA rules│  │ -Hash/IP/Domain   │ │
│  │ -Ensemble │  │ -MITRE map   │  │                   │ │
│  └──────────┘  └──────────────┘  └───────────────────┘ │
└──────────────────────────┬──────────────────────────────┘
                           │ Event Bus (asyncio Queue)
┌──────────────────────────┴──────────────────────────────┐
│                   Feature Engineering                    │
│  15-dim process vectors │ 10-dim network vectors = 25D  │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────┐
│                  Sensor / Agent Layer                     │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐ │
│  │ Process   │  │ File System  │  │ Network           │ │
│  │ Monitor   │  │ Monitor      │  │ Monitor           │ │
│  │ (psutil)  │  │ (watchdog)   │  │ (psutil+socket)   │ │
│  └──────────┘  └──────────────┘  └───────────────────┘ │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────┐
│              SQLite Event Store + Response Engine         │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# One-command setup and run
bash setup_and_run.sh
```

Or manually:

```bash
# Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create data directories
mkdir -p data/models data/quarantine

# Start the EDR
python3 run_edr.py
```

Open the dashboard at **http://localhost:8080**.

## Running Simulations

In a separate terminal (while the EDR is running):

```bash
source venv/bin/activate

# Interactive menu
python3 tests/simulate_malware.py

# Run all 7 simulations
python3 tests/simulate_malware.py --all

# Run a specific simulation (1-7)
python3 tests/simulate_malware.py --test 2
```

All simulations are **safe** — no actual damage is performed. They create artifacts and patterns that trigger the EDR's detections.

| # | Simulation | Triggers | MITRE |
|---|---|---|---|
| 1 | Discovery Commands | IOA-006 | T1082 |
| 2 | LaunchAgent Persistence | IOA-004 | T1543.001 |
| 3 | Encoded Execution | IOA-008 | T1140 |
| 4 | Reverse Shell Pattern | IOA-002/013 | T1059.004 |
| 5 | Data Exfiltration | IOA-014 | T1027 |
| 6 | Ransomware | IOA-012/014/016 | T1486 |
| 7 | Crypto Miner | IOA-011 | T1496 |

## Components

### Sensor Layer (`sensor/`)

- **Process Monitor** — Polls process table via `psutil` every 1s. Tracks creation, termination, parent-child trees, SHA256 hashes of executables.
- **File Monitor** — Uses `watchdog` to watch sensitive directories (`/tmp`, `/etc`, `~/Library/LaunchAgents`, etc.). Calculates file entropy, tracks permissions, flags risky extensions.
- **Network Monitor** — Tracks outbound connections per process, monitors for non-standard ports, high-volume transfers, and private IP usage.
- **Event Collector** — Async event bus (`asyncio.Queue`) routing telemetry to the feature pipeline, storage, and detection engine.

### Feature Engineering (`features/`)

Extracts 25-dimensional behavioral vectors per process:

| Dimension | Features |
|---|---|
| Process (15D) | CPU mean/std, memory RSS/growth, child spawn rate, threads, open files, connections, cmdline length/entropy, shell parent, tree depth, exe entropy, lifetime, unsigned |
| Network (10D) | Unique destinations, bytes sent/recv rate, connection frequency, avg duration, non-standard port, private IP, DNS rate, failed connections, unique ports |

Features are normalized via `StandardScaler` fitted online after 200 samples.

### ML Detection Engine (`ml/`)

- **Isolation Forest** — scikit-learn with 200 estimators, 5% contamination. Retrained every 1000 samples.
- **Autoencoder** — PyTorch neural network (25 &rarr; 64 &rarr; 32 &rarr; 16 &rarr; 8 &rarr; 16 &rarr; 32 &rarr; 64 &rarr; 25). High reconstruction error = anomaly. Retrained every 500 samples.
- **Ensemble** — Weighted combination: 40% IF + 40% AE + 20% behavioral rules. Outputs threat score 0-100 with severity classification.
- **Model Store** — Persists trained models to `data/models/` for warm-start on restart.

### Behavioral Detection (`detection/`)

17 IOA rules mapped to MITRE ATT&CK:

| Rule | Name | Tactic | Severity |
|---|---|---|---|
| IOA-001 | Shell from web process | Execution | High |
| IOA-002 | Reverse shell pattern | Execution | Critical |
| IOA-003 | Privilege escalation | Privilege Escalation | High |
| IOA-004 | LaunchAgent/Daemon persistence | Persistence | High |
| IOA-005 | Credential access (Keychain) | Credential Access | High |
| IOA-006 | Discovery command sequence | Discovery | Medium |
| IOA-007 | Data exfiltration pattern | Exfiltration | High |
| IOA-008 | Encoded command execution | Defense Evasion | High |
| IOA-009 | Process injection indicator | Defense Evasion | Critical |
| IOA-010 | Unusual parent-child process | Execution | Medium |
| IOA-011 | Cryptocurrency miner | Impact | Medium |
| IOA-012 | Ransomware indicator | Impact | Critical |
| IOA-013 | Non-standard port comms | Command and Control | Low |
| IOA-014 | High entropy file creation | Defense Evasion | Medium |
| IOA-015 | Sensitive directory modification | Persistence | Medium |
| IOA-016 | Mass file operations | Impact | High |
| IOA-017 | User/group discovery | Discovery | Low |

Plus IOC matching (SHA256 hashes, IP addresses, domains) via a local threat intel database.

### Response Engine (`response/`)

- `kill_process(pid)` — SIGKILL malicious process
- `quarantine_file(path)` — Move to quarantine directory with metadata
- `suspend_process(pid)` — SIGSTOP for review
- `network_isolate()` — Log-only in PoC mode

Auto-responds for threats scoring above 80. All actions logged with full audit trail.

### Dashboard (`dashboard/`)

Dark-themed web console at `http://localhost:8080`:

- **Real-time alert feed** with severity indicators and WebSocket push
- **Alert stats bar** — Critical/High/Medium/Low counts
- **Endpoint health gauge** — 0-100 score
- **Process table** with threat scores and kill actions
- **Process tree visualization** — parent-child relationships
- **ML metrics panel** — model status, severity distribution, ensemble weights
- **MITRE ATT&CK matrix** — heatmap of detected techniques
- **Response action log** — audit trail of all response actions

### REST API

| Endpoint | Method | Description |
|---|---|---|
| `/api/alerts` | GET | Paginated alerts with severity/status filters |
| `/api/alerts/stats` | GET | Alert counts by severity |
| `/api/alerts/<id>/acknowledge` | POST | Acknowledge an alert |
| `/api/alerts/<id>/resolve` | POST | Resolve an alert |
| `/api/processes` | GET | Active process list with threat scores |
| `/api/process/<pid>/tree` | GET | Process tree for a PID |
| `/api/ml/metrics` | GET | ML model performance metrics |
| `/api/events/timeline` | GET | Event timeline for charts |
| `/api/mitre/matrix` | GET | MITRE ATT&CK coverage data |
| `/api/response/kill/<pid>` | POST | Kill a process |
| `/api/response/quarantine` | POST | Quarantine a file |
| `/api/response/log` | GET | Response action audit log |
| `/api/status` | GET | System status and uptime |

## Project Structure

```
EDR/
├── run_edr.py                    # Main entry point
├── config.yaml                   # Central configuration
├── requirements.txt              # Dependencies
├── setup_and_run.sh              # One-command setup
├── sensor/                       # Telemetry collection
│   ├── process_monitor.py        # Process tracking (psutil)
│   ├── file_monitor.py           # File system events (watchdog)
│   ├── network_monitor.py        # Network connections
│   └── collector.py              # Async event bus
├── features/                     # Feature engineering
│   ├── process_features.py       # 15-dim process vectors
│   ├── file_features.py          # 8-dim file vectors
│   ├── network_features.py       # 10-dim network vectors
│   └── pipeline.py               # Orchestrator + normalization
├── ml/                           # ML detection
│   ├── isolation_forest.py       # Isolation Forest detector
│   ├── autoencoder.py            # PyTorch autoencoder
│   ├── ensemble.py               # Multi-model scorer
│   └── model_store.py            # Model persistence
├── detection/                    # Behavioral analysis
│   ├── behavioral_rules.py       # 17 IOA rules
│   ├── mitre_attack.py           # ATT&CK technique mapping
│   ├── threat_intel.py           # IOC matching
│   └── alert_manager.py          # Alert lifecycle
├── response/                     # Response actions
│   └── response_engine.py        # Kill, quarantine, isolate
├── storage/                      # Data persistence
│   └── database.py               # SQLite event store
├── dashboard/                    # Web console
│   ├── app.py                    # Flask + WebSocket server
│   ├── templates/index.html      # Dashboard SPA
│   └── static/                   # CSS + JS
└── tests/
    └── simulate_malware.py       # 7 safe attack simulations
```

## Configuration

Edit `config.yaml` to tune:

- **Sensor polling intervals** and watched directories
- **ML hyperparameters** — estimators, contamination, hidden dims, learning rate, retrain intervals
- **Ensemble weights** — IF/AE/behavioral balance
- **Detection thresholds** — normal/suspicious/malicious/critical score boundaries
- **Response policy** — auto-respond threshold, quarantine directory
- **Dashboard** — host, port

## Dependencies

- `psutil` — Process and system monitoring
- `watchdog` — File system event monitoring
- `scikit-learn` — Isolation Forest, StandardScaler
- `torch` — Autoencoder neural network
- `numpy` — Numerical computing
- `flask` — Web framework
- `flask-socketio` — WebSocket real-time updates
- `eventlet` — Async worker for Flask-SocketIO
- `pyyaml` — Configuration parsing

## Disclaimer

This is a **proof of concept for educational and security research purposes**. It is not intended for production use. The response engine operates in PoC mode — network isolation is log-only and process actions require confirmation via the dashboard.
