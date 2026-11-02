"""Malformed query controls must produce client errors, never server errors."""
import pytest
from tests.test_v7_workspace import client, post


@pytest.mark.parametrize('controls', [
    {'limit': None}, {'limit': []}, {'offset': {}}, {'limit': True},
    {'limit': 'many'}, {'order': 'random'}, {'filters': {'status': []}},
])
def test_invalid_query_controls(client, controls):
    response = post(client, 'workspace/query', controls)
    assert response.status_code == 400
