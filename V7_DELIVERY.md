# V7 investigation workspace

Open `/soc`, connect with an authorized SOC key, then choose **Grafana / Log Analytics** in the site menu. Queries go through the authenticated Flask gateway; service credentials stay on the server. The native chart and evidence view stay inside the website. The separate Grafana dashboard remains available for Grafana administration.

## Included

- Shared event, IP, host, case and time context across search, charts, network, endpoint and Copilot screens.
- Canonical event IDs, exact raw-record deduplication, occurrence provenance and correlation across upload batches.
- Global search, sortable event selection, evidence export, manual cases, assignment/SLA and a case merge API.
- Saved investigations and queries, query history, versioned bounded detection rules and rule testing.
- Evidence drawer, original batch hashes, application custody hash chain and browser print/PDF reports. External anchoring is required to protect against privileged rewriting of the entire chain.
- Authenticated resumable SSE, collector heartbeat, actual service availability and local public-analysis handoff.
- Read-only Copilot based on queried records and evidence IDs. Optional Ollama commentary is labeled separately; without a model, the deterministic evidence summary still works.

## Free deployment configuration

Use the existing free Render service and Grafana Cloud account. `LAB_LOKI_URL`, `LAB_LOKI_USER`, `LAB_LOKI_PASSWORD` enable reads. Set separate `LAB_LOKI_WRITE_USER` and `LAB_LOKI_WRITE_TOKEN` credentials with logs:write scope to enable the private upload export checkbox. Export is opt-in; public analysis does not automatically upload logs to Loki. Failed exports remain in the application outbox for retry through the workspace sync action.

Set `LAB_EVIDENCE_SIGNING_KEY` for a stable signing secret; otherwise the owner API key signs gateway exports. Keep the signing key stable when rotating authentication credentials. Copy configuration variable names from `.env.example`; keep real keys outside Git.

Render's free ephemeral filesystem can lose SQLite state on restart/deployment. A persistent local Linux Compose installation retains the database in its Docker volume. Loki retention does not preserve SOC cases, notes or custody records. Back up those separately.

GNS3, Wazuh and Ollama need actual running services and reachable URLs. Their screens report offline/unconfigured until those services respond. No deployment of these runtimes is implied by adding their adapters. Docker/WSL system configuration is not changed by this release.

## Validation

131 Python tests passed locally. V7, UI, Atlas and platform browser suites passed with Microsoft Edge, covering private ingestion, cross-screen evidence, local analysis, site-contained Loki views, languages and responsive layouts. CI repeats Python, JavaScript and isolated browser checks on Linux.
