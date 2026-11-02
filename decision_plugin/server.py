import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .protocol import DecisionTurn, decide

MAX_BYTES = 8192


def reject_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate JSON key')
        out[key] = value
    return out


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/api/v1/decision-turns':
            self._send_json(404, {'error': 'not_found'})
            return
        try:
            if self.headers.get('Content-Type') != 'application/json':
                raise ValueError('content type must be application/json')
            if self.headers.get('Transfer-Encoding'):
                raise ValueError('chunked requests are not supported')
            if len(self.headers.get_all('Content-Length', [])) != 1:
                raise ValueError('exactly one content length is required')
            size = int(self.headers['Content-Length'])
            if not 0 < size <= MAX_BYTES:
                raise ValueError('invalid content length')
            body = self.rfile.read(size)
            if len(body) != size:
                raise ValueError('truncated request body')
            turn = DecisionTurn.parse(json.loads(body, object_pairs_hook=reject_duplicate_keys))
            payload, status = decide(turn), 200
        except (ValueError, TypeError, UnicodeError):
            payload, status = {'error': 'invalid_decision_turn'}, 400
        self._send_json(status, payload)

    def _send_json(self, status, payload):
        data = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    ThreadingHTTPServer(('127.0.0.1', 8081), Handler).serve_forever()


if __name__ == '__main__':
    main()
