import json
import os
import queue
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Deque, Dict

from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

from log_engine import analyze_logs, build_report, parse_logs

BASE_DIR = Path(__file__).resolve().parent
DATASET_DIR = BASE_DIR / 'datasets'
DB_PATH = BASE_DIR / 'analysis.db'
MAX_UPLOAD_SIZE = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {'log', 'txt', 'json'}
RATE_WINDOW = 60
RATE_LIMITS: Dict[str, int] = {
    'default': 120,
    'analyze': 30,
    'report': 40,
    'stream': 10,
}

_request_bucket: Dict[str, Deque[float]] = defaultdict(deque)
_bucket_lock = threading.Lock()
stream_queue: 'queue.Queue[Dict[str, Any]]' = queue.Queue(maxsize=1000)
_heartbeat_lock = threading.Lock()
_heartbeat_started = False


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
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


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace('+00:00', 'Z')


def _json_error(message: str, status: int = 400) -> Response:
    return jsonify({'error': message, 'meta': {'status': status}}), status


def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _allowed_file(filename: str) -> bool:
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def _client_ip() -> str:
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        first_hop = forwarded_for.split(',')[0].strip()
        if first_hop:
            return first_hop
    return request.remote_addr or 'unknown'


def _bucket_key() -> str:
    endpoint = request.endpoint or 'unknown'
    return f'{_client_ip()}::{endpoint}'


def _rate_limit_for_endpoint() -> int:
    endpoint = request.endpoint or ''
    if endpoint in {'analyze_endpoint'}:
        return RATE_LIMITS['analyze']
    if endpoint in {'report_endpoint'}:
        return RATE_LIMITS['report']
    if endpoint in {'stream'}:
        return RATE_LIMITS['stream']
    return RATE_LIMITS['default']


def _rate_limited(bucket_key: str) -> bool:
    now = time.time()
    limit = _rate_limit_for_endpoint()
    with _bucket_lock:
        bucket = _request_bucket[bucket_key]
        while bucket and now - bucket[0] > RATE_WINDOW:
            bucket.popleft()
        if len(bucket) >= limit:
            return True
        bucket.append(now)
        return False


def _push_stream_event(event: Dict[str, Any]) -> None:
    try:
        stream_queue.put_nowait(event)
    except queue.Full:
        pass


def _ensure_heartbeat_started() -> None:
    global _heartbeat_started
    with _heartbeat_lock:
        if _heartbeat_started:
            return
        threading.Thread(target=_seed_stream_heartbeat, daemon=True).start()
        _heartbeat_started = True


def _store_analysis(source: str, analysis: Dict[str, Any]) -> int:
    with _db_conn() as conn:
        cur = conn.execute(
            '''
            INSERT INTO analyses (created_at, source, total_logs, total_alerts, risk, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (
                _utc_now_iso(),
                source,
                int(analysis.get('total', 0)),
                len(analysis.get('alerts', [])),
                str(analysis.get('risk', 'low')),
                json.dumps(analysis),
            ),
        )
        conn.commit()
        analysis_id = int(cur.lastrowid)
    return analysis_id


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path='')
    app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE
    init_db()

    @app.errorhandler(HTTPException)
    def handle_http_error(exc: HTTPException) -> Response:
        message = exc.description if isinstance(exc.description, str) else 'HTTP error'
        return _json_error(message, exc.code or 500)

    @app.errorhandler(413)
    def handle_too_large(_: Any) -> Response:
        return _json_error('File too large (max 5 MB)', 413)

    @app.errorhandler(Exception)
    def handle_unexpected_error(_: Exception) -> Response:
        return _json_error('Internal server error', 500)

    @app.after_request
    def apply_security_headers(resp: Response) -> Response:
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        resp.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        return resp

    @app.before_request
    def guardrails() -> Any:
        _ensure_heartbeat_started()
        if _rate_limited(_bucket_key()):
            return _json_error('Rate limit exceeded', 429)

    return app


app = create_app()


@app.route('/')
def index() -> Response:
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/api/health')
def health() -> Response:
    return jsonify({'status': 'ok', 'service': 'AKT Log Intelligence API', 'time': _utc_now_iso()})


@app.route('/api/datasets')
def list_datasets() -> Response:
    if not DATASET_DIR.exists():
        return jsonify({'datasets': []})
    names = sorted([p.name for p in DATASET_DIR.iterdir() if p.is_file()])
    return jsonify({'datasets': names})


@app.route('/api/datasets/<name>')
def read_dataset(name: str) -> Response:
    candidate = (DATASET_DIR / name).resolve()
    dataset_root = DATASET_DIR.resolve()
    try:
        candidate.relative_to(dataset_root)
    except ValueError:
        return _json_error('Invalid dataset path', 400)
    if not candidate.exists() or not candidate.is_file():
        return _json_error('Dataset not found', 404)
    content = candidate.read_text(encoding='utf-8', errors='ignore')
    return jsonify({'name': name, 'content': content})


@app.route('/api/analyze', methods=['POST'])
def analyze_endpoint() -> Response:
    source = 'manual'
    raw_logs = ''

    if request.files.get('file'):
        file = request.files['file']
        if not file.filename or not _allowed_file(file.filename):
            return _json_error('Only .log, .txt, .json files are allowed', 400)

        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > MAX_UPLOAD_SIZE:
            return _json_error('File too large (max 5 MB)', 400)

        raw_logs = file.read().decode('utf-8', errors='ignore')
        source = 'file_upload'
    else:
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return _json_error('Invalid JSON payload', 400)
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
        return _json_error('No log payload provided', 400)

    parsed = parse_logs(raw_logs)
    analysis = analyze_logs(parsed)
    analysis_id = _store_analysis(source, analysis)

    _push_stream_event(
        {
            'analysis_id': analysis_id,
            'created_at': _utc_now_iso(),
            'total': analysis.get('total', 0),
            'alerts': len(analysis.get('alerts', [])),
            'risk': analysis.get('risk', 'low'),
        }
    )

    return jsonify({'analysis_id': analysis_id, 'analysis': analysis})


@app.route('/api/report', methods=['POST'])
def report_endpoint() -> Response:
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return _json_error('Invalid JSON payload', 400)
    report_type = str(payload.get('report_type', 'Daily'))

    analysis = payload.get('analysis')
    if analysis is None:
        analysis_id = payload.get('analysis_id')
        if analysis_id is None:
            return _json_error('analysis or analysis_id is required', 400)
        with _db_conn() as conn:
            row = conn.execute('SELECT payload_json FROM analyses WHERE id = ?', (analysis_id,)).fetchone()
        if not row:
            return _json_error('Analysis record not found', 404)
        analysis = json.loads(row['payload_json'])

    report = build_report(analysis, report_type=report_type)
    return jsonify({'report_type': report_type, 'report': report})


@app.route('/api/analysis/history')
def analysis_history() -> Response:
    with _db_conn() as conn:
        rows = conn.execute(
            'SELECT id, created_at, source, total_logs, total_alerts, risk FROM analyses ORDER BY id DESC LIMIT 25'
        ).fetchall()
    return jsonify(
        {
            'items': [
                {
                    'id': row['id'],
                    'created_at': row['created_at'],
                    'source': row['source'],
                    'total_logs': row['total_logs'],
                    'total_alerts': row['total_alerts'],
                    'risk': row['risk'],
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
                yield f"data: {json.dumps(item)}\n\n"
            except queue.Empty:
                yield "event: keepalive\ndata: {}\n\n"

    resp = Response(event_generator(), mimetype='text/event-stream')
    resp.headers['Cache-Control'] = 'no-cache'
    resp.headers['X-Accel-Buffering'] = 'no'
    return resp


def _seed_stream_heartbeat() -> None:
    while True:
        _push_stream_event(
            {
                'analysis_id': None,
                'created_at': _utc_now_iso(),
                'message': 'stream-alive',
            }
        )
        time.sleep(30)


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', os.environ.get('APP_PORT', '5000'))),
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true',
    )
