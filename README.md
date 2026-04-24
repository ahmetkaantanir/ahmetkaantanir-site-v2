# Log Intelligence Lab

> **Interactive mini-SIEM platform** — upload real logs, detect attacks, correlate events, and generate security reports. Built with Python + Flask + vanilla JS.

---

## Architecture

```
Log Source (file / API / dataset)
        │
        ▼
 ┌─────────────────────────────────────────┐
 │           Flask Backend (app.py)        │
 │  • File upload validation (5 MB limit)  │
 │  • Rate limiting (token-bucket)         │
 │  • Security headers (CSP, HSTS, etc.)   │
 └───────────────┬─────────────────────────┘
                 │
        ┌────────▼────────┐
        │  log_engine.py  │
        │  • Multi-format parser             │
        │    Apache / Auth / Firewall / JSON │
        │  • Attack signature detection      │
        │    SQLi · XSS · Dir Traversal      │
        │  • Analyzer                        │
        │    IP counts · error rate · top EP │
        │  • Brute-force alert rules         │
        │  • Correlation engine              │
        │    scan → then login               │
        │  • Z-Score anomaly detection       │
        │  • IP reputation scoring           │
        │  • Report builder                  │
        └────────┬────────┘
                 │
  ┌──────────────▼──────────────────┐
  │         SQLite (analysis.db)    │
  │  Analysis history · 25 records  │
  └──────────────┬──────────────────┘
                 │
  ┌──────────────▼──────────────────────────────────────┐
  │              Frontend (index.html + script.js)       │
  │  • KPI Dashboard     • Chart.js (traffic, IP dist.)  │
  │  • Alert list        • Correlation panel             │
  │  • Anomaly panel     • IP Reputation panel           │
  │  • Analysis history  • Report generator + download   │
  │  • Drag & Drop upload  • SSE real-time stream        │
  └──────────────────────────────────────────────────────┘
```

## Features

| Area | Details |
|------|---------|
| **Log Parsing** | Apache/Nginx, Linux auth (SSH), firewall DROP/ACCEPT, JSON API events |
| **Collection** | File upload (.log/.txt/.json, max 5 MB), API payload, built-in demo datasets |
| **Attack Detection** | SQL Injection, XSS, Directory Traversal signatures |
| **Alerting** | 10+ failed logins, 1000 req/min threshold, nighttime anomaly |
| **Correlation** | Scan-then-login scenario per IP |
| **Anomaly Detection** | Z-Score on hourly traffic distribution |
| **Visualization** | KPI cards, hourly traffic chart, top-IP bar chart, reputation & geo panels |
| **Reporting** | Daily/Weekly text report, downloadable .txt |
| **Security** | CSP headers, rate limiting, path traversal guard, upload content validation |
| **Persistence** | SQLite — last 25 analyses stored and browsable |
| **Real-time** | SSE stream (`/api/stream`) — heartbeat + analysis events |

## Stack

- **Backend**: Python 3.11+, Flask 3.0, SQLite
- **Frontend**: Vanilla JS (ES2020), Chart.js 4, Space Grotesk / Sora fonts
- **Testing**: pytest

## Run Locally

```powershell
# 1. Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start server
python app.py

# 4. Open browser → http://127.0.0.1:5000
```

## Run Tests

```powershell
.\.venv\Scripts\pytest tests/ -v
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/datasets` | List available datasets |
| GET | `/api/datasets/<name>` | Load a dataset |
| POST | `/api/analyze` | Analyze logs (file or JSON body) |
| POST | `/api/report` | Generate report |
| GET | `/api/analysis/history` | Last 25 analyses |
| GET | `/api/stream` | SSE event stream |

### POST /api/analyze

```json
// JSON body
{ "raw_logs": "192.168.1.1 - - [21/Apr/2026:10:00:00 +0300] \"GET / HTTP/1.1\" 200 1024" }

// or multipart/form-data with field: file
```

### POST /api/report

```json
{ "report_type": "Daily", "analysis_id": 42 }
```

## Demo Datasets

| Dataset | Contents |
|---------|----------|
| `apache.log` | 60+ entries: normal traffic, brute force, SQLi, XSS, directory traversal, scanner |
| `auth.log` | 40+ entries: two SSH brute-force attacks, legitimate logins, night-time anomaly |
| `mixed.log` | All log types combined: correlation scenario (scan → brute force → API attack) |

## Deploy to Render (Free)

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your repo — Render auto-detects `render.yaml`
4. Click **Deploy**

The `render.yaml` in this repo handles the build and start commands.

## Production Notes

- Put Flask behind Nginx and enforce HTTPS / HSTS
- Use a production WSGI server (Waitress on Windows, Gunicorn on Linux)
- Disable debug: `FLASK_DEBUG=false`
- Move rate limiting to Redis-backed limiter for scale
- Add real GeoIP (MaxMind GeoLite2) and AbuseIPDB reputation lookup
