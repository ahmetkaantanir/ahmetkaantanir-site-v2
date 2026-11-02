"""Normal page navigation must not spend the API request budget."""
from tests.test_v7_workspace import client


def test_static_files_remain_available_across_repeated_navigation(client, monkeypatch):
    import app
    monkeypatch.setitem(app.RATE_LIMITS, 'default', 2)
    for path in ['/soc.js', '/v7.js', '/atlas.js', '/translations.js', '/soc.css']:
        assert client.get(path).status_code == 200


def test_api_request_limits_are_still_enforced(client, monkeypatch):
    import app
    monkeypatch.setitem(app.RATE_LIMITS, 'default', 2)
    assert client.get('/api/health').status_code == 200
    assert client.get('/api/health').status_code == 200
    assert client.get('/api/health').status_code == 429
