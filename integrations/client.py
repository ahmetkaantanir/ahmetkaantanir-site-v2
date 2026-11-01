"""Bounded, administrator-configured JSON clients; no browser-supplied origins."""
import base64
import hashlib
import json
import os
import ssl
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class IntegrationError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


_wazuh_lock = threading.Lock()
_wazuh_cached = {}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def origin(service):
    value = os.getenv(f"LAB_{service.upper()}_URL", "").rstrip("/")
    if not value:
        raise IntegrationError("Service is not configured")
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment or
            parsed.path not in {"", "/"}):
        raise IntegrationError("Invalid service origin")
    # Plain HTTP is an explicit administrator choice for a private local network.
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        if os.getenv("LAB_ALLOW_PRIVATE_HTTP") != "true":
            raise IntegrationError("Private HTTP requires LAB_ALLOW_PRIVATE_HTTP=true")
    return value


def _request_json(service, path, params=None, method="GET", payload=None, authorization=None):
    address = origin(service) + path
    if params:
        address += "?" + urlencode(params)
    headers = {"Accept": "application/json"}
    access_id = os.getenv(f"LAB_{service.upper()}_CF_ACCESS_CLIENT_ID", "")
    access_secret = os.getenv(f"LAB_{service.upper()}_CF_ACCESS_CLIENT_SECRET", "")
    if bool(access_id) != bool(access_secret):
        raise IntegrationError("Both Cloudflare Access credentials are required")
    if access_id:
        headers['CF-Access-Client-Id'] = access_id
        headers['CF-Access-Client-Secret'] = access_secret
    token = os.getenv(f"LAB_{service.upper()}_TOKEN", "")
    user = os.getenv(f"LAB_{service.upper()}_USER", "")
    password = os.getenv(f"LAB_{service.upper()}_PASSWORD", "")
    if authorization:
        headers['Authorization'] = authorization
    elif token:
        headers["Authorization"] = "Bearer " + token
    elif user and password:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    try:
        ca_file = os.getenv(f"LAB_{service.upper()}_CA_FILE") or None
        context = ssl.create_default_context(cafile=ca_file)
        with build_opener(NoRedirect, HTTPSHandler(context=context)).open(Request(address, data=body, headers=headers, method=method), timeout=45 if service == 'ollama' else 8) as response:
            data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise IntegrationError("Upstream response exceeds 2 MB")
            return json.loads(data)
    except HTTPError as exc:
        raise IntegrationError("Upstream rejected the request", status=exc.code) from exc
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        # Never leak origins, credentials, upstream bodies or exception strings.
        raise IntegrationError("Upstream unavailable or returned invalid JSON") from exc


def _wazuh_bearer(rejected=None):
    user, password = os.getenv('LAB_WAZUH_USER', ''), os.getenv('LAB_WAZUH_PASSWORD', '')
    if not user or not password:
        raise IntegrationError('Wazuh API user and password are required')
    fingerprint = hashlib.sha256(json.dumps([origin('wazuh'), user, password,
        os.getenv('LAB_WAZUH_CA_FILE'), os.getenv('LAB_WAZUH_CF_ACCESS_CLIENT_ID'),
        os.getenv('LAB_WAZUH_CF_ACCESS_CLIENT_SECRET')]).encode()).hexdigest()
    with _wazuh_lock:
        if (_wazuh_cached.get('fingerprint') == fingerprint and
                _wazuh_cached.get('until', 0) > time.monotonic() and
                _wazuh_cached.get('token') != rejected):
            return _wazuh_cached['token']
        basic = 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()
        result = _request_json('wazuh', '/security/user/authenticate', method='POST', authorization=basic)
        data = result.get('data') if isinstance(result, dict) else None
        token = data.get('token') if isinstance(data, dict) else None
        if not isinstance(token, str) or not 1 <= len(token) <= 16384 or '\r' in token or '\n' in token:
            raise IntegrationError('Wazuh returned an invalid authentication response')
        _wazuh_cached.update(fingerprint=fingerprint, token=token, until=time.monotonic()+300)
        return token


def fetch_json(service, path, params=None, method="GET", payload=None):
    automatic_wazuh = service == 'wazuh' and not os.getenv('LAB_WAZUH_TOKEN') and (
        os.getenv('LAB_WAZUH_USER') or os.getenv('LAB_WAZUH_PASSWORD'))
    if not automatic_wazuh:
        return _request_json(service, path, params, method, payload)
    token = _wazuh_bearer()
    try:
        return _request_json(service, path, params, method, payload, 'Bearer '+token)
    except IntegrationError as exc:
        if exc.status != 401 or method != 'GET':
            raise
        token = _wazuh_bearer(rejected=token)
        return _request_json(service, path, params, method, payload, 'Bearer '+token)


def grafana_link(host=None, start=None, end=None):
    base = origin("grafana_public") if os.getenv('LAB_GRAFANA_PUBLIC_URL') else origin("grafana")
    return base + "/d/log-lab/security-operations?" + urlencode({
        "var-host": host or "", "from": start or "now-1h", "to": end or "now"})
