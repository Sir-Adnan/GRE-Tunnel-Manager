"""HTTP/TLS routing assertions for the private namespace suite (stdlib only)."""
import http.client
import http.server
import ssl
import sys
import threading


if sys.argv[1] == 'serve':
    cert, key = sys.argv[2:4]
    servers = []
    for port, label, tls in [(28005, 'A', False), (28006, 'B', False),
                             (28007, 'A', True), (28008, 'B', True)]:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = self.server.label.encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(('0.0.0.0', port), Handler)
        server.label = label
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()
else:
    mode, port, host, path, expected, cert = sys.argv[2:8]
    connect_ip = sys.argv[8] if len(sys.argv) > 8 else '127.0.0.1'
    if mode == 'http':
        connection = http.client.HTTPConnection(connect_ip, int(port), timeout=3)
    else:
        context = ssl.create_default_context(cafile=cert)
        # Connect to loopback while preserving SNI and certificate verification.
        connection = http.client.HTTPSConnection(host, int(port), timeout=3, context=context)
        import socket
        connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection((connect_ip, int(port)), timeout)
    connection.request('GET', path, headers={'Host': host + ':' + port})
    response = connection.getresponse()
    body = response.read().decode()
    assert response.status == 200 and body in expected.split('|'), (response.status, body, expected)
    print(body)
    connection.close()
