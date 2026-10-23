"""Plain HTTP readiness fixture; used only inside the test network namespace."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        expected = self.path == '/ready/live' and self.headers.get('Host') == 'health.example.com'
        self.send_response(204 if expected and Path(sys.argv[1]).exists() else 503)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(('0.0.0.0', 28004), Handler).serve_forever()
