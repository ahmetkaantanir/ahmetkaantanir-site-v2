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

### Full database backup and recovery

The local maintenance command snapshots SQLite through its online backup API, including committed WAL data. It retains raw batches, events, cases, notes, saved investigations, rules and custody records. It checks database integrity and references and reports a SHA-256 plus record counts. It never replaces an existing destination.

```sh
python -m backend.backup backup --source analysis.db --output backups/soc-2026-11-02.db
python -m backend.backup verify --source backups/soc-2026-11-02.db
python -m backend.backup restore --source backups/soc-2026-11-02.db --output recovered.db
```

For recovery, stop the application, point `LOG_LAB_DB_PATH` at the verified recovered file and restart. Preserve the original database until the recovered workspace has been checked. Store backups outside ephemeral hosting and protect them like the source logs. These commands require filesystem access to the service database; a local backup cannot recover a remote database that has already been lost. Docker images and Git exclude the backup directory.

### Release checks

CI runs on feature branches and pull requests. Pull requests also run the isolated UI, Atlas, platform and V7 browser suites. Live checks explicitly require V7 controls and assets, so an older V6 deployment cannot pass as the completed release.

142 Python tests and 14 JavaScript tests passed locally on 2026-11-02. V7, UI, Atlas and platform browser suites passed with Microsoft Edge, covering private ingestion, cross-screen evidence, local analysis, site-contained Loki views, languages and responsive layouts. The new checks cover malformed query controls, local filter/order parity, delayed-script startup and recovery of a complete workspace including WAL data and pre-upgrade databases. CI repeats Python, JavaScript and isolated browser checks on Linux.
