# AKT Log Intelligence Lab

Interactive mini-SIEM platform with training content, log analysis engine, dashboard, alerts, correlation, and report generation.

## Features

- Multi-source logs: Apache/Nginx, syslog/auth, firewall, JSON API events
- Collection methods:
  - File upload (.log, .txt, .json)
  - API payload ingestion
  - Built-in demo datasets
- Parsing pipeline:
  - Regex parsers for web/auth/firewall logs
  - JSON parser for structured events
  - Field extraction: IP, timestamp, request, status
- Analytics engine:
  - Suspicious activity rules
  - SQLi/XSS/Directory Traversal signature detection
  - Correlation: scan then login attempts
  - Statistics: top IP, top endpoints, error rate
- Visualization:
  - KPI dashboard
  - Hourly traffic and IP distribution charts
  - Reputation, geo distribution, anomaly panels
- Alerting:
  - 10 failed logins
  - 1000 requests/min threshold
  - Attack signature alerts
- Reporting:
  - Daily/Weekly report generation
  - Downloadable TXT report
- Security hardening basics:
  - File extension and size checks
  - Simple API rate limiting
  - Input validation and path traversal guard

## Backend stack

- Python + Flask
- SQLite persistence for analysis history

## Run locally

1. Create and activate a Python environment.
2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Start app:

```powershell
python app.py
```

4. Open in browser:

- http://127.0.0.1:5000

## API endpoints

- `GET /api/health`
- `GET /api/datasets`
- `GET /api/datasets/<name>`
- `POST /api/analyze`
  - multipart form-data with `file`
  - or JSON body with `raw_logs` and optional `api_lines`
- `POST /api/report`
  - JSON body with `analysis_id` or inline `analysis`
- `GET /api/analysis/history`
- `GET /api/stream` (SSE)

## Production notes

- Put Flask behind Nginx and enforce HTTPS.
- Add strict upload content scanning and WAF rules.
- Move rate limiting to reverse proxy or Redis-backed limiter for scale.
