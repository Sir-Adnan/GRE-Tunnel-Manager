"""Test-only held TCP session and PROXY v1/v2 receiver, inside private namespaces."""
from pathlib import Path
import socket
import sys
import threading
import time


def exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size-len(data))
        if not chunk:
            raise EOFError()
        data.extend(chunk)
    return bytes(data)


def exchange(conn, payload):
    conn.sendall(len(payload).to_bytes(4, 'big') + payload)
    assert exact(conn, len(payload)+4) == b'tcp:' + payload


def proxy_connection(conn, expected):
    with conn:
        conn.settimeout(4)
        try:
            header = exact(conn, 16)
            if header.startswith(b'\r\n\r\n\x00\r\nQUIT\n'):
                assert header[12] >> 4 == 2
                data = exact(conn, int.from_bytes(header[14:16], 'big'))
                source = socket.inet_ntoa(data[:4]) if header[12] == 0x21 and header[13] == 0x11 else None
            else:
                while not header.endswith(b'\r\n') and len(header) < 108:
                    header += exact(conn, 1)
                fields = header.decode('ascii').strip().split()
                assert fields[:2] == ['PROXY', 'TCP4'], fields
                source = fields[2]
            size = int.from_bytes(exact(conn, 4), 'big')
            assert source == expected, (source, expected)
            assert size <= 262144
            conn.sendall(b'tcp:' + exact(conn, size))
        except (EOFError, TimeoutError, ConnectionError):
            pass


if sys.argv[1] == 'hold':
    port, ready, proceed = int(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])
    with socket.create_connection(('127.0.0.1', port), timeout=4) as conn:
        exchange(conn, b'before-reload')
        ready.touch()
        deadline = time.monotonic()+10
        while not proceed.exists():
            if time.monotonic() > deadline:
                raise TimeoutError('Reload did not finish')
            time.sleep(.05)
        exchange(conn, b'after-reload')
    print('PASS: an established TCP session survived HAProxy worker reload.')
else:
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', 28003))
        server.listen()
        while True:
            conn, peer = server.accept()
            threading.Thread(target=proxy_connection, args=(conn, sys.argv[2]), daemon=True).start()
