import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest

from decision_plugin.server import Handler

VALID = dict(protocol_version='v0.1', invocation_id='inv-1', tenant_id='t-1',
             agent_id='a-1', run_id='r-1', turn_id='turn-1', user_input='hello')


@pytest.fixture()
def server():
    srv = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)


def request(port, data, headers=None, path='/api/v1/decision-turns'):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
    try:
        conn.request('POST', path, body=data, headers=headers or {'Content-Type': 'application/json'})
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()


def test_http_success(server):
    status, body = request(server, json.dumps(VALID).encode())
    assert status == 200
    assert body == {'protocol_version': 'v0.1', 'invocation_id': 'inv-1',
                    'kind': 'final_response', 'text': 'Accepted: hello'}


@pytest.mark.parametrize('body', [
    b'not json', b'[]', b'{}',
    b'{"protocol_version":"v0.1","protocol_version":"v1"}',
    json.dumps({**VALID, 'user_input': ' '}).encode(),
    json.dumps({**VALID, 'user_input': 'é' * 2500}).encode(),
])
def test_http_rejects_bad_payload(server, body):
    status, response = request(server, body)
    assert status == 400
    assert response['error'] == 'invalid_decision_turn'


def test_http_rejects_wrong_content_type(server):
    status, _ = request(server, json.dumps(VALID).encode(), {'Content-Type': 'text/plain'})
    assert status == 400


def test_http_rejects_large_request(server):
    status, _ = request(server, b' ' * 8193)
    assert status == 400


def test_http_rejects_wrong_path(server):
    status, _ = request(server, json.dumps(VALID).encode(), path='/incorrect')
    assert status == 404
