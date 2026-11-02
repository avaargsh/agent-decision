import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .protocol import DecisionTurn, decide

MAX_BYTES = 8192


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/api/v1/decision-turns':
            self.send_error(404)
            return
        try:
            if self.headers.get('Content-Type') != 'application/json':
                raise ValueError('content type must be application/json')
            size = int(self.headers.get('Content-Length', '-1'))
            if not 0 < size <= MAX_BYTES:
                raise ValueError('invalid content length')
            turn = DecisionTurn.parse(json.loads(self.rfile.read(size)))
            payload, status = decide(turn), 200
        except (ValueError, TypeError, json.JSONDecodeError):
            payload, status = {'error': 'invalid_decision_turn'}, 400
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    ThreadingHTTPServer(('127.0.0.1', 8081), Handler).serve_forever()


if __name__ == '__main__':
    main()
