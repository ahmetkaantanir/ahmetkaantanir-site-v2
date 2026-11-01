"""Exercise the HTTP authentication boundary against a local test server."""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from integrations.client import IntegrationError, fetch_json, grafana_link


@pytest.fixture
def service(monkeypatch):
    state = {'issued': 0, 'requests': [], 'expire_once': False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, payload):
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())

        def do_POST(self):
            state['requests'].append((self.path, dict(self.headers)))
            expected = 'Basic ' + base64.b64encode(b'api-user:api-password').decode()
            if self.path == '/security/user/authenticate' and self.headers.get('Authorization') == expected:
                state['issued'] += 1
                self.reply(200, {'data': {'token': 'test-issued-token-' + str(state['issued'])}, 'error': 0})
            else:
                self.reply(401, {'error': 'unauthorized'})

        def do_GET(self):
            state['requests'].append((self.path, dict(self.headers)))
            if self.path == '/agents':
                if state['expire_once']:
                    state['expire_once'] = False
                    self.reply(401, {'error': 'expired'})
                elif self.headers.get('Authorization') == 'Bearer test-issued-token-' + str(state['issued']) and state['issued']:
                    self.reply(200, {'data': {'affected_items': [{'id': '001', 'status': 'active'}]}, 'error': 0})
                else:
                    self.reply(401, {'error': 'unauthorized'})
            elif self.path == '/access':
                if self.headers.get('CF-Access-Client-Id') == 'test-client' and self.headers.get('CF-Access-Client-Secret') == 'test-secret':
                    self.reply(200, {'ok': True})
                else:
                    self.reply(403, {'error': 'access denied'})
            else:
                self.reply(404, {})

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = 'http://127.0.0.1:' + str(server.server_port)
    monkeypatch.setenv('LAB_WAZUH_URL', base)
    monkeypatch.setenv('LAB_WAZUH_USER', 'api-user')
    monkeypatch.setenv('LAB_WAZUH_PASSWORD', 'api-password')
    monkeypatch.delenv('LAB_WAZUH_TOKEN', raising=False)
    yield base, state
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_wazuh_exchanges_basic_credentials_for_reusable_bearer(service):
    _, state = service
    assert fetch_json('wazuh', '/agents')['data']['affected_items'][0]['id'] == '001'
    fetch_json('wazuh', '/agents')
    assert state['issued'] == 1
    assert all(headers['Authorization'].startswith('Bearer ') for path, headers in state['requests'] if path == '/agents')


def test_wazuh_refreshes_expired_jwt_once(service):
    _, state = service
    fetch_json('wazuh', '/agents')
    state['expire_once'] = True
    assert fetch_json('wazuh', '/agents')['error'] == 0
    assert state['issued'] == 2


def test_cloudflare_machine_credentials_stay_service_scoped(service, monkeypatch):
    base, state = service
    monkeypatch.setenv('LAB_LOKI_URL', base)
    monkeypatch.setenv('LAB_LOKI_CF_ACCESS_CLIENT_ID', 'test-client')
    monkeypatch.setenv('LAB_LOKI_CF_ACCESS_CLIENT_SECRET', 'test-secret')
    assert fetch_json('loki', '/access')['ok'] is True
    fetch_json('wazuh', '/agents')
    assert all('cf-access-client-secret' not in {k.lower() for k in headers} for path, headers in state['requests'] if path == '/agents')


def test_incomplete_access_credentials_fail_closed(service, monkeypatch):
    base, state = service
    monkeypatch.setenv('LAB_LOKI_URL', base)
    monkeypatch.setenv('LAB_LOKI_CF_ACCESS_CLIENT_ID', 'test-client')
    monkeypatch.delenv('LAB_LOKI_CF_ACCESS_CLIENT_SECRET', raising=False)
    with pytest.raises(IntegrationError):
        fetch_json('loki', '/access')
    assert state['requests'] == []


def test_grafana_browser_link_does_not_use_private_docker_origin(monkeypatch):
    monkeypatch.setenv('LAB_GRAFANA_URL', 'https://internal-grafana.example')
    monkeypatch.setenv('LAB_GRAFANA_PUBLIC_URL', 'https://grafana.example')
    assert grafana_link('test-host').startswith('https://grafana.example/d/log-lab/')
