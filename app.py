import json
import os
import queue
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict

from flask import Flask, Response, jsonify, request, send_from_directory

from log_engine import analyze_logs, build_report, parse_logs

BASE_DIR = Path(__file__).resolve().parent
DATASET_DIR = BASE_DIR / 'datasets'
DB_PATH = BASE_DIR / 'analysis.db'
MAX_UPLOAD_SIZE = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {'log', 'txt', 'json'}
RATE_LIMIT = 60
RATE_WINDOW = 60

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path='')

_request_bucket: Dict[str, Deque[float]] = defaultdict(deque)
stream_queue: 'queue.Queue[Dict[str, Any]]' = queue.Queue(maxsize=1000)


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            source TEXT NOT NULL,
            total_logs INTEGER NOT NULL,
            total_alerts INTEGER NOT NULL,
            risk TEXT NOT NULL,
            payload_json TEXT NOT NULL
        )
        '''
    )
    conn.commit()
    conn.close()


def _allowed_file(filename: str) -> bool:
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def _rate_limited(client_ip: str) -> bool:
    now = time.time()
    bucket = _request_bucket[client_ip]
    while bucket and now - bucket[0] > RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT:
        return True
    bucket.append(now)
    return False


def _push_stream_event(event: Dict[str, Any]) -> None:
    try:
        stream_queue.put_nowait(event)
    except queue.Full:
        pass


def _store_analysis(source: str, analysis: Dict[str, Any]) -> int:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        '''
        INSERT INTO analyses (created_at, source, total_logs, total_alerts, risk, payload_json)
        VALUES (?, ?, ?, ?, ?, ?)
        ''',
        (
            datetime.utcnow().isoformat(),
            source,
            int(analysis.get('total', 0)),
            len(analysis.get('alerts', [])),
            str(analysis.get('risk', 'low')),
            json.dumps(analysis),
        ),
    )
    conn.commit()
    analysis_id = int(cur.lastrowid)
    conn.close()
    return analysis_id


@app.before_request
def guardrails() -> Any:
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')
    if _rate_limited(client_ip):
        return jsonify({'error': 'Rate limit exceeded'}), 429


@app.route('/')
def index() -> Response:
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/api/health')
def health() -> Response:
    return jsonify({'status': 'ok', 'service': 'AKT Log Intelligence API'})


@app.route('/api/datasets')
def list_datasets() -> Response:
    if not DATASET_DIR.exists():
        return jsonify({'datasets': []})
    names = sorted([p.name for p in DATASET_DIR.iterdir() if p.is_file()])
    return jsonify({'datasets': names})


@app.route('/api/datasets/<name>')
def read_dataset(name: str) -> Response:
    candidate = (DATASET_DIR / name).resolve()
    if DATASET_DIR.resolve() not in candidate.parents:
        return jsonify({'error': 'Invalid dataset path'}), 400
    if not candidate.exists() or not candidate.is_file():
        return jsonify({'error': 'Dataset not found'}), 404
    content = candidate.read_text(encoding='utf-8', errors='ignore')
    return jsonify({'name': name, 'content': content})


@app.route('/api/analyze', methods=['POST'])
def analyze_endpoint() -> Response:
    source = 'manual'
    raw_logs = ''

    if request.files.get('file'):
        file = request.files['file']
        if not file.filename or not _allowed_file(file.filename):
            return jsonify({'error': 'Only .log, .txt, .json files are allowed'}), 400

        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > MAX_UPLOAD_SIZE:
            return jsonify({'error': 'File too large (max 5 MB)'}), 400

        raw_logs = file.read().decode('utf-8', errors='ignore')
        source = 'file_upload'
    else:
        payload = request.get_json(silent=True) or {}
        raw_logs = str(payload.get('raw_logs', '')).strip()
        api_lines = payload.get('api_lines', [])
        if isinstance(api_lines, list) and api_lines:
            api_serialized = []
            for row in api_lines:
                if isinstance(row, dict):
                    api_serialized.append(json.dumps(row))
                elif isinstance(row, str):
                    api_serialized.append(row)
            raw_logs = '\n'.join([raw_logs] + api_serialized).strip()
            source = 'api_ingest'

    if not raw_logs:
        return jsonify({'error': 'No log payload provided'}), 400

    parsed = parse_logs(raw_logs)
    analysis = analyze_logs(parsed)
    analysis_id = _store_analysis(source, analysis)

    _push_stream_event(
        {
            'analysis_id': analysis_id,
            'created_at': datetime.utcnow().isoformat(),
            'total': analysis.get('total', 0),
            'alerts': len(analysis.get('alerts', [])),
            'risk': analysis.get('risk', 'low'),
        }
    )

    return jsonify({'analysis_id': analysis_id, 'analysis': analysis})


@app.route('/api/report', methods=['POST'])
def report_endpoint() -> Response:
    payload = request.get_json(silent=True) or {}
    report_type = str(payload.get('report_type', 'Daily'))

    analysis = payload.get('analysis')
    if analysis is None:
        analysis_id = payload.get('analysis_id')
        if analysis_id is None:
            return jsonify({'error': 'analysis or analysis_id is required'}), 400
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute('SELECT payload_json FROM analyses WHERE id = ?', (analysis_id,)).fetchone()
        conn.close()
        if not row:
            return jsonify({'error': 'Analysis record not found'}), 404
        analysis = json.loads(row[0])

    report = build_report(analysis, report_type=report_type)
    return jsonify({'report_type': report_type, 'report': report})


@app.route('/api/analysis/history')
def analysis_history() -> Response:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        'SELECT id, created_at, source, total_logs, total_alerts, risk FROM analyses ORDER BY id DESC LIMIT 25'
    ).fetchall()
    conn.close()
    return jsonify(
        {
            'items': [
                {
                    'id': row[0],
                    'created_at': row[1],
                    'source': row[2],
                    'total_logs': row[3],
                    'total_alerts': row[4],
                    'risk': row[5],
                }
                for row in rows
            ]
        }
    )


@app.route('/api/stream')
def stream() -> Response:
    def event_generator():
        while True:
            try:
                item = stream_queue.get(timeout=20)
                yield f"data: {json.dumps(item)}\\n\\n"
            except queue.Empty:
                yield 'event: keepalive\\ndata: {}\\n\\n'

    return Response(event_generator(), mimetype='text/event-stream')


def _seed_stream_heartbeat() -> None:
    while True:
        _push_stream_event(
            {
                'analysis_id': None,
                'created_at': datetime.utcnow().isoformat(),
                'message': 'stream-alive',
            }
        )
        time.sleep(30)


if __name__ == '__main__':
    init_db()
    threading.Thread(target=_seed_stream_heartbeat, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=True)
