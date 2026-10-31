"""Authenticated SOC API: durable evidence, incident triage, search and reports."""
from __future__ import annotations

import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, request
from soc_engine import RULES, inspect

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
        """)
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        pass

    def now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def audit(conn, action, subject):
        conn.execute("INSERT INTO soc_audit(at,action,subject) VALUES (?,?,?)",
                     (now(), action[:64], str(subject)[:180]))

    @bp.before_request
    def require_key():
        key = os.getenv("LOG_LAB_API_KEY", "")
        if not key or len(key) < 24:
            return jsonify({"error": "SOC workspace is disabled until a strong LOG_LAB_API_KEY is configured"}), 503
        if not hmac.compare_digest(request.headers.get("X-API-Key", ""), key):
            return jsonify({"error": "Unauthorized"}), 401

    @bp.get("/rules")
    def rules():
        return jsonify({"rules": [{"id": k, **v} for k, v in RULES.items()]})

    @bp.post("/ingest")
    def ingest():
        file = request.files.get("file")
        if file is not None:
            if not file.filename or file.filename.rsplit(".", 1)[-1].lower() not in {"log", "txt", "json"}:
                return jsonify({"error": "Only .log, .txt, .json files allowed"}), 400
            raw = file.read(5 * 1024 * 1024 + 1)
            if len(raw) > 5 * 1024 * 1024:
                return jsonify({"error": "File limit 5MB"}), 413
            try:
                text = raw.decode("utf-8", "strict")
            except UnicodeDecodeError:
                return jsonify({"error": "UTF-8 input required"}), 400
            source = "file_upload"
        else:
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict) or not isinstance(payload.get("raw_logs"), str):
                return jsonify({"error": "raw_logs must be a string"}), 400
            text = payload["raw_logs"]
            source = "api"
        try:
            result = inspect(text)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        moment = now()
        with connection() as db:
            existing = db.execute("SELECT id FROM soc_batches WHERE sha256=?", (result["sha256"],)).fetchone()
            if existing:
                return jsonify({"batch_id": existing["id"], "duplicate": True, "sha256": result["sha256"],
                                "events": result["total"], "alert_count": len(result["alerts"]), "risk": result["risk"]}), 200
            cur = db.execute(
                "INSERT INTO soc_batches(created_at,source,sha256,event_count,alert_count,risk) VALUES (?,?,?,?,?,?)",
                (moment, source, result["sha256"], result["total"], len(result["alerts"]), result["risk"]))
            batch = cur.lastrowid
            db.executemany(
                "INSERT INTO soc_events(batch_id,event_id,timestamp,source,ip,user_name,raw_json) VALUES (?,?,?,?,?,?,?)",
                [(batch, e["event_id"], e["timestamp"], e["source"], e["ip"], e["user"],
                  json.dumps(e, ensure_ascii=False)) for e in result["events"]])
            db.executemany(
                """INSERT INTO soc_cases
                (batch_id,alert_id,rule_id,severity,ip,reason,evidence_json,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                [(batch, a["alert_id"], a["rule_id"], a["severity"], a["ip"], a["reason"],
                  json.dumps(a["event_ids"]), moment, moment) for a in result["alerts"]])
            audit(db, "ingest", batch)
        return jsonify({"batch_id": batch, "duplicate": False, "sha256": result["sha256"],
                        "events": result["total"], "alert_count": len(result["alerts"]),
                        "risk": result["risk"], "sources": result["sources"],
                        "unknown_timestamps": result["unknown_timestamps"],
                        "limitations": result["limitations"]}), 201

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

    @bp.get("/events")
    def events():
        try:
            limit = int(request.args.get("limit", "100"))
        except ValueError:
            return jsonify({"error": "limit must be a number"}), 400
        limit = min(max(limit, 1), 500)
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
        if query:
            clauses.append("raw_json LIKE ? ESCAPE '\\'")
            params.append("%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        if start:
            clauses.append("timestamp >= ?")
            params.append(start)
        if end:
            clauses.append("timestamp <= ?")
            params.append(end)
        statement = "SELECT raw_json FROM soc_events"
        if clauses:
            statement += " WHERE " + " AND ".join(clauses)
        statement += " ORDER BY id DESC LIMIT ?"
        with connection() as db:
            rows = db.execute(statement, params + [limit]).fetchall()
        return jsonify({"items": [json.loads(r["raw_json"]) for r in rows]})

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
        if status not in STATUSES or not isinstance(notes, str) or len(notes) > 4000:
            return jsonify({"error": "Invalid status or notes (max 4000 characters)"}), 400
        with connection() as db:
            row = db.execute("SELECT id FROM soc_cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                return jsonify({"error": "Case not found"}), 404
            db.execute("UPDATE soc_cases SET status=?,notes=?,updated_at=? WHERE id=?",
                       (status, notes, now(), case_id))
            audit(db, "case_update", case_id)
        return jsonify({"ok": True, "case_id": case_id})

    @bp.get("/cases/<int:case_id>/timeline")
    def case_timeline(case_id):
        with connection() as db:
            row = db.execute("SELECT batch_id,evidence_json FROM soc_cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                return jsonify({"error": "Case not found"}), 404
            ids = set(json.loads(row["evidence_json"]))
            events = [json.loads(r["raw_json"]) for r in db.execute(
                "SELECT raw_json FROM soc_events WHERE batch_id=? ORDER BY timestamp", (row["batch_id"],))]
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

    return bp
