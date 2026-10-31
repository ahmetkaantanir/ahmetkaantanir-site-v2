# Log Intelligence Lab — Security Upgrade Roadmap

This branch is the working area for rebuilding the existing Log Intelligence Lab into a modular security analytics platform. The original main branch remains unchanged until changes are reviewed and tested.

## Architecture and milestones

1. **Security baseline:** protect source code and stored logs from HTTP access; authenticated API access, safe HTML rendering, trusted reverse proxy configuration, input validation, upload limits, audit trails, secure error handling.
2. **Ingestion and normalization:** Apache/Nginx, Linux SSH, Windows Events, Sysmon, firewall, Suricata; explicit unknown fields; UTC timestamps, source metadata, event IDs, deduplication, malformed-line isolation.
3. **Detection:** configurable time-window rules for brute force, password spraying, web attacks, network scans, suspicious processes; evidence-linked alerts; MITRE ATT&CK mappings and Sigma interoperability.
4. **Correlation and cases:** ordered, time-bounded correlations, incident workflows, analyst notes, false-positive tracking, risk score explanations.
5. **Investigation:** forensic timelines, SHA-256 integrity metadata, original log preservation, searchable event store, controlled exports and reports.
6. **Intelligence and analytics:** opt-in threat-intelligence enrichment, explainable anomaly detection, behavioral baselines and privacy-preserving AI-assisted summaries.
7. **SOC interface:** overview, log explorer, detection rules, incident queue, threat hunting, forensic timeline, reporting, source health, configuration.
8. **Quality:** unit/integration/E2E/security/load tests, fixture-based detection validation, CI, documentation, deploy hardening.

## Acceptance requirements

- Do not call unknown IPs clean or fabricate GeoIP results.
- A single invalid log entry must not terminate a batch.
- A detection must cite supporting event IDs and preserve the source timestamps.
- No sensitive source files, databases, tokens, or private logs served as public assets.
- No claims of production readiness without end-to-end testing.
- Deployments require configured authentication, HTTPS, secure storage and explicit retention rules.

## Progress

- [x] GitHub development branch created.
- [x] Implementation roadmap committed.
- [ ] Security baseline implementation and verification.
- [ ] Additional parsers, detections, correlation, investigations, AI and dashboard.
