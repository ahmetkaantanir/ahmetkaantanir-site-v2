"""Authenticated SOC API: durable evidence, incident triage, search and reports."""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, g, jsonify, request
from soc_engine import RULES, inspect
from platform_auth import principal, permitted
from integrations.platform import create_platform_blueprint
from backend.schema import initialize as initialize_workspace
from backend.storage import ingest_text,custody
from backend.workspace import create_workspace_blueprint
from backend import cloud_sync

STATUSES = {"new", "investigating", "resolved", "false_positive"}


def create_soc_blueprint(db_path: Path) -> Blueprint:
    bp = Blueprint("soc", __name__, url_prefix="/api/soc")
    db_path.parent.mkdir(parents=True, exist_ok=True)

    def connection():
        conn = sqlite3.connect(str(db_path), timeout=12)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=12000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    with connection() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS soc_batches (
            id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, source TEXT NOT NULL,
            sha256 TEXT UNIQUE NOT NULL, event_count INTEGER NOT NULL,
            alert_count INTEGER NOT NULL, risk TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS soc_events (
            id INTEGER PRIMARY KEY, batch_id INTEGER NOT NULL,
            event_id TEXT NOT NULL, timestamp TEXT, source TEXT NOT NULL,
            ip TEXT, user_name TEXT, raw_json TEXT NOT NULL,
            FOREIGN KEY(batch_id) REFERENCES soc_batches(id)
        );
        CREATE INDEX IF NOT EXISTS ix_soc_time ON soc_events(timestamp);
        CREATE INDEX IF NOT EXISTS ix_soc_ip ON soc_events(ip);
        CREATE INDEX IF NOT EXISTS ix_soc_source ON soc_events(source);
        CREATE INDEX IF NOT EXISTS ix_soc_user ON soc_events(user_name);
        CREATE INDEX IF NOT EXISTS ix_soc_host ON soc_events(json_extract(raw_json,'$.host'));
        CREATE TABLE IF NOT EXISTS soc_cases (
            id INTEGER PRIMARY KEY, batch_id INTEGER NOT NULL,
            alert_id TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new', ip TEXT, reason TEXT NOT NULL,
            evidence_json TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            FOREIGN KEY(batch_id) REFERENCES soc_batches(id)
        );
        CREATE INDEX IF NOT EXISTS ix_soc_cases_status ON soc_cases(status);
        CREATE TABLE IF NOT EXISTS soc_audit (
            id INTEGER PRIMARY KEY, at TEXT NOT NULL,
            action TEXT NOT NULL, subject TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS soc_watchlist (
            id INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL,
            label TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(kind,value)
        );
        CREATE TABLE IF NOT EXISTS soc_raw_batches (
            batch_id INTEGER PRIMARY KEY REFERENCES soc_batches(id), raw_text TEXT NOT NULL
        );
        """)
    initialize_workspace(connection)
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        pass

    def now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def audit(conn, action, subject):
        conn.execute("INSERT INTO soc_audit(at,action,subject) VALUES (?,?,?)",
                     (now(), action[:64], (str(subject) + ' | actor=' + g.soc_principal['name'])[:180]))

    @bp.before_request
    def require_key():
        if not os.getenv("LOG_LAB_PRINCIPALS") and len(os.getenv("LOG_LAB_API_KEY", "")) < 24:
            return jsonify({"error": "SOC workspace is disabled until a strong LOG_LAB_API_KEY is configured"}), 503
        identity = principal(request.headers.get("X-API-Key", ""))
        if not identity:
            return jsonify({"error": "Unauthorized"}), 401
        g.soc_principal = identity
        if not permitted(identity, request.method, request.path):
            return jsonify({"error": "This role cannot perform the requested action"}), 403

    @bp.get("/rules")
    def rules():
        return jsonify({"rules": [{"id": k, **v} for k, v in RULES.items()]})

    @bp.post("/ingest")
    def ingest():
        sync=False;source_id=None
        file = request.files.get("file")
        if file is not None:
            if not file.filename or file.filename.rsplit(".", 1)[-1].lower() not in {"log", "txt", "json", "jsonl", "ndjson"}:
                return jsonify({"error": "Only .log, .txt, .json files allowed"}), 400
            raw = file.read(5 * 1024 * 1024 + 1)
            if len(raw) > 5 * 1024 * 1024:
                return jsonify({"error": "File limit 5MB"}), 413
            try:
                text = raw.decode("utf-8", "strict")
            except UnicodeDecodeError:
                return jsonify({"error": "UTF-8 input required"}), 400
            source = "file_upload"
            sync=request.form.get('sync_loki','false')=='true'
            source_id=request.form.get('source_id')
        else:
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict) or not isinstance(payload.get("raw_logs"), str):
                return jsonify({"error": "raw_logs must be a string"}), 400
            text = payload["raw_logs"]
            source = "api"
            sync=payload.get('sync_loki',False)
            source_id=payload.get('source_id')
        try:
            result,status=ingest_text(connection,audit,text,source,g.soc_principal['name'],source_id,sync)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if sync:result['cloud_sync']=cloud_sync.flush(connection)
        return jsonify(result),status

    @bp.get("/summary")
    def summary():
        with connection() as db:
            batch = db.execute("SELECT COUNT(*) n, COALESCE(SUM(event_count),0) events, COALESCE(SUM(alert_count),0) alerts FROM soc_batches").fetchone()
            statuses = db.execute("SELECT status, COUNT(*) n FROM soc_cases GROUP BY status").fetchall()
            src = db.execute("SELECT source, COUNT(*) n FROM soc_events GROUP BY source ORDER BY n DESC LIMIT 10").fetchall()
            recent = db.execute("SELECT created_at,risk,event_count,alert_count FROM soc_batches ORDER BY id DESC LIMIT 10").fetchall()
        return jsonify({"batches": batch["n"], "events": batch["events"], "alerts": batch["alerts"],
                        "cases": {r["status"]: r["n"] for r in statuses},
                        "sources": {r["source"]: r["n"] for r in src},
                        "recent": [dict(r) for r in recent]})

    @bp.get("/intelligence")
    def intelligence():
        with connection() as db:
            total = db.execute("SELECT COUNT(*) FROM soc_events").fetchone()[0]
            missing_time = db.execute("SELECT COUNT(*) FROM soc_events WHERE timestamp IS NULL").fetchone()[0]
            missing_ip = db.execute("SELECT COUNT(*) FROM soc_events WHERE ip IS NULL").fetchone()[0]
            unknown = db.execute("SELECT COUNT(*) FROM soc_events WHERE source='unknown'").fetchone()[0]
            rows = db.execute("SELECT ip, COUNT(*) events FROM soc_events WHERE ip IS NOT NULL GROUP BY ip ORDER BY events DESC, ip LIMIT 50").fetchall()
            cases = {r['ip']: r['n'] for r in db.execute("SELECT ip, COUNT(*) n FROM soc_cases GROUP BY ip")}
            severities = {r['severity']: r['n'] for r in db.execute("SELECT severity, COUNT(*) n FROM soc_cases GROUP BY severity")}
            timeline = [dict(r) for r in db.execute("SELECT substr(timestamp,1,13) hour, COUNT(*) events FROM soc_events WHERE timestamp IS NOT NULL GROUP BY hour ORDER BY hour DESC LIMIT 24")]
        ips = []
        for row in rows:
            address = ipaddress.ip_address(row['ip'])
            nets = ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24') if address.version == 4 else ('2001:db8::/32',)
            scope = ('documentation' if any(address in ipaddress.ip_network(n) for n in nets) else
                     'loopback' if address.is_loopback else 'link_local' if address.is_link_local else
                     'multicast' if address.is_multicast else 'unspecified' if address.is_unspecified else
                     'private' if address.is_private else 'public' if address.is_global else 'reserved')
            ips.append({**dict(row), 'scope': scope, 'version': address.version,
                        'alerts': cases.get(row['ip'], 0), 'reputation': 'unknown', 'country': None})
        return jsonify({'total': total, 'missing_time': missing_time, 'missing_ip': missing_ip,
                        'unparsed': unknown, 'ips': ips, 'ip_limit': 50, 'geoip': 'unavailable',
                        'severities': severities, 'timeline': list(reversed(timeline))})

    @bp.get("/events")
    def events():
        try:
            limit = int(request.args.get("limit", "100"))
            offset = int(request.args.get("offset", "0"))
        except ValueError:
            return jsonify({"error": "limit and offset must be numbers"}), 400
        if offset < 0 or offset > 10000000:
            return jsonify({"error": "offset out of range"}), 400
        limit = min(max(limit, 1), 500)
        if any(request.args.get(k) for k in ('severity','mitre','rule_id','status','source_id','event_id')):
            from backend.query import search_events
            filters={k:request.args[k] for k in ('ip','source','user','host','outcome','action','q','start','end','severity','mitre','rule_id','status','source_id','event_id') if request.args.get(k)}
            try:
                with connection() as db:return jsonify(search_events(db,filters,limit,offset))
            except ValueError as exc:return jsonify(error=str(exc)),400
        ip = request.args.get("ip", "")[:80]
        source = request.args.get("source", "")[:80]
        query = request.args.get("q", "")[:120]
        start = request.args.get("start", "")[:48]
        end = request.args.get("end", "")[:48]
        clauses = []
        params: list = []
        for field, value in (("ip", ip), ("source", source)):
            if value:
                clauses.append(field + "=?")
                params.append(value)
        for arg, column in (("user", "user_name"), ("host", "json_extract(raw_json,'$.host')"),
                            ("outcome", "json_extract(raw_json,'$.outcome')"),
                            ("action", "json_extract(raw_json,'$.action')")):
            value = request.args.get(arg, "")[:256]
            if value:
                clauses.append(column + "=?")
                params.append(value)
        if query:
            clauses.append("raw_json LIKE ? ESCAPE '\\'")
            params.append("%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        bounds = []
        for value, operator in ((start, ">="), (end, "<=")):
            if value:
                try:
                    moment = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    if moment.tzinfo is None:
                        raise ValueError()
                    normalized = moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                except (ValueError, OverflowError):
                    return jsonify({"error": "start/end require ISO timestamps with timezone"}), 400
                bounds.append(moment)
                clauses.append("julianday(timestamp) " + operator + " julianday(?)")
                params.append(normalized)
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            return jsonify({"error": "start must not be after end"}), 400
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with connection() as db:
            total = db.execute("SELECT COUNT(*) FROM soc_events" + where, params).fetchone()[0]
            rows = db.execute("SELECT raw_json FROM soc_events" + where + " ORDER BY id DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
        return jsonify({"items": [json.loads(r["raw_json"]) for r in rows], "total": total,
                        "limit": limit, "offset": offset, "has_more": offset + len(rows) < total})

    @bp.get("/source-health")
    def source_health():
        with connection() as db:
            rows = db.execute("""SELECT e.source, COUNT(*) events,
                SUM(CASE WHEN timestamp IS NULL THEN 1 ELSE 0 END) missing_time,
                SUM(CASE WHEN ip IS NULL THEN 1 ELSE 0 END) missing_ip,
                MIN(timestamp) first_event, MAX(timestamp) last_event,
                MAX(b.created_at) last_ingested
                FROM soc_events e JOIN soc_batches b ON b.id=e.batch_id
                GROUP BY e.source ORDER BY events DESC""").fetchall()
        return jsonify({"items": [dict(r) for r in rows], "heartbeat_available": False})

    @bp.get("/watchlist")
    def watchlist():
        with connection() as db:
            rows = db.execute("SELECT * FROM soc_watchlist ORDER BY id DESC LIMIT 100").fetchall()
            items = []
            for row in rows:
                column = {"ip": "ip", "user": "user_name", "host": "json_extract(raw_json,'$.host')"}[row['kind']]
                matches = db.execute("SELECT COUNT(*) n, MAX(timestamp) last_seen FROM soc_events WHERE " + column + "=?", (row['value'],)).fetchone()
                items.append({**dict(row), "matches": matches['n'], "last_seen": matches['last_seen']})
        return jsonify({"items": items, "limit": 100})

    @bp.post("/watchlist")
    def add_watchlist():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400
        kind, value, label = payload.get('kind'), payload.get('value'), payload.get('label', '')
        if not isinstance(kind, str) or kind not in {'ip', 'user', 'host'} or not isinstance(value, str) or not value.strip() or len(value) > 256 or not isinstance(label, str) or len(label) > 120:
            return jsonify({"error": "Valid kind, value (1-256) and label (0-120) required"}), 400
        value = value.strip()
        if kind == 'ip':
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                return jsonify({"error": "Invalid IP address"}), 400
        with connection() as db:
            if db.execute("SELECT COUNT(*) FROM soc_watchlist").fetchone()[0] >= 100:
                return jsonify({"error": "Watchlist limit reached (100)"}), 400
            cur = db.execute("INSERT OR IGNORE INTO soc_watchlist(kind,value,label,created_at) VALUES (?,?,?,?)", (kind, value, label.strip(), now()))
            if not cur.rowcount:
                return jsonify({"error": "Entry already exists"}), 409
            audit(db, 'watchlist_add', cur.lastrowid)
            item_id = cur.lastrowid
        return jsonify({"id": item_id, "kind": kind, "value": value}), 201

    @bp.delete("/watchlist/<int:item_id>")
    def delete_watchlist(item_id):
        with connection() as db:
            if not db.execute("DELETE FROM soc_watchlist WHERE id=?", (item_id,)).rowcount:
                return jsonify({"error": "Entry not found"}), 404
            audit(db, 'watchlist_delete', item_id)
        return jsonify({"deleted": item_id})

    @bp.get("/cases")
    def cases():
        status = request.args.get("status", "")
        if status and status not in STATUSES:
            return jsonify({"error": "Unknown status"}), 400
        with connection() as db:
            sql = "SELECT * FROM soc_cases"
            args = []
            if status:
                sql += " WHERE status=?"
                args.append(status)
            sql += " ORDER BY id DESC LIMIT 200"
            data = [dict(r) for r in db.execute(sql, args)]
        return jsonify({"items": data})

    @bp.patch("/cases/<int:case_id>")
    def update_case(case_id):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400
        status, notes = payload.get("status"), payload.get("notes", "")
        if not isinstance(status, str) or status not in STATUSES or not isinstance(notes, str) or len(notes) > 4000:
            return jsonify({"error": "Invalid status or notes (max 4000 characters)"}), 400
        with connection() as db:
            row = db.execute("SELECT id FROM soc_cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                return jsonify({"error": "Case not found"}), 404
            db.execute("UPDATE soc_cases SET status=?,notes=?,updated_at=? WHERE id=?",
                       (status, notes, now(), case_id))
            audit(db, "case_update", case_id)
            custody(db,g.soc_principal['name'],'case_update',case_id)
        return jsonify({"ok": True, "case_id": case_id})

    @bp.get("/cases/<int:case_id>/timeline")
    def case_timeline(case_id):
        with connection() as db:
            row = db.execute("SELECT batch_id,evidence_json FROM soc_cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                return jsonify({"error": "Case not found"}), 404
            ids = set(json.loads(row["evidence_json"]))
            if ids and all(i.startswith('evt-') for i in ids):
                events=[json.loads(r[0]) for r in db.execute('SELECT raw_json FROM soc_events WHERE event_id IN (SELECT value FROM json_each(?)) ORDER BY julianday(timestamp),id',(json.dumps(list(ids)),))]
            else:
                events = [json.loads(r["raw_json"]) for r in db.execute(
                    "SELECT raw_json FROM soc_events WHERE batch_id=? ORDER BY julianday(timestamp), id", (row["batch_id"],))]
            custody(db,g.soc_principal['name'],'case_timeline_read',case_id)
        return jsonify({"case_id": case_id, "items": [e for e in events if e["event_id"] in ids]})

    @bp.get("/cases/<int:case_id>/explain")
    def explain(case_id):
        with connection() as db:
            row = db.execute("SELECT * FROM soc_cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                return jsonify({"error": "Case not found"}), 404
        case = dict(row)
        return jsonify({"type": "evidence_based_summary", "ai_generated": False,
                        "headline": f"{case['rule_id']} / {case['severity']}",
                        "summary": case["reason"], "mitre": RULES.get(case["rule_id"], {}).get("mitre"),
                        "next_steps": ["Inspect linked source log entries and their original timestamps.",
                                       "Confirm user, host and business context before escalating.",
                                       "Record analyst decisions in the case notes."],
                        "warning": "This is deterministic guidance, not an AI verdict or proof of compromise."})

    @bp.get("/audit")
    def get_audit():
        with connection() as db:
            rows = db.execute("SELECT at,action,subject FROM soc_audit ORDER BY id DESC LIMIT 100").fetchall()
        return jsonify({"items": [dict(r) for r in rows]})

    bp.register_blueprint(create_platform_blueprint(connection, audit))
    bp.register_blueprint(create_workspace_blueprint(connection,audit))
    return bp
