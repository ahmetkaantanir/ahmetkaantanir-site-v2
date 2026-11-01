"""Bounded, administrator-configured JSON clients; no browser-supplied origins."""
import base64
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class IntegrationError(Exception):
    pass


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


def fetch_json(service, path, params=None, method="GET", payload=None):
    address = origin(service) + path
    if params:
        address += "?" + urlencode(params)
    headers = {"Accept": "application/json"}
    token = os.getenv(f"LAB_{service.upper()}_TOKEN", "")
    user = os.getenv(f"LAB_{service.upper()}_USER", "")
    password = os.getenv(f"LAB_{service.upper()}_PASSWORD", "")
    if token:
        headers["Authorization"] = "Bearer " + token
    elif user and password:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    try:
        with build_opener(NoRedirect).open(Request(address, data=body, headers=headers, method=method), timeout=45 if service == 'ollama' else 8) as response:
            data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise IntegrationError("Upstream response exceeds 2 MB")
            return json.loads(data)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        # Never leak origins, credentials, upstream bodies or exception strings.
        raise IntegrationError("Upstream unavailable or returned invalid JSON") from exc


def grafana_link(host=None, start=None, end=None):
    base = origin("grafana")
    return base + "/d/log-lab/security-operations?" + urlencode({
        "var-host": host or "", "from": start or "now-1h", "to": end or "now"})
