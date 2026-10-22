"""Tiny TCP/UDP echo probe used only inside isolated test namespaces."""
import socket
import os
import sys
import threading


def receive_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size-len(chunks))
        if not chunk:
            raise EOFError('Peer closed before the expected response arrived')
        chunks.extend(chunk)
    return bytes(chunks)


def udp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('0.0.0.0', 28001))
        while True:
            payload, peer = sock.recvfrom(4096)
            sock.sendto(b'udp:' + payload, peer)


def tcp_connection(conn):
    with conn:
        conn.settimeout(4)
        try:
            while True:
                size = int.from_bytes(receive_exact(conn, 4), 'big')
                if size > 262144:
                    return
                conn.sendall(b'tcp:' + receive_exact(conn, size))
        except (EOFError, TimeoutError, ConnectionError):
            pass  # Health checks connect without sending application data.


if sys.argv[1] == 'mss':
    interface, target, maximum = sys.argv[2], socket.inet_aton(sys.argv[3]), int(sys.argv[4])
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003)) as sock:
        sock.bind((interface, 0))
        sock.settimeout(4)
        while True:
            packet = sock.recv(65535)
            if len(packet) < 40 or packet[0] >> 4 != 4:
                continue
            ip_size = (packet[0] & 15) * 4
            if packet[9] != 6 or packet[16:20] != target or not packet[ip_size+13] & 2:
                continue
            options = packet[ip_size+20:ip_size+(packet[ip_size+12] >> 4)*4]
            while options:
                kind = options[0]
                if kind == 0:
                    break
                if kind == 1:
                    options = options[1:]
                    continue
                length = options[1]
                if kind == 2 and length == 4:
                    mss = int.from_bytes(options[2:4], 'big')
                    assert 0 < mss <= maximum, (mss, maximum)
                    print(f'PASS: MSS {mss} <= {maximum} on {interface}')
                    sys.exit(0)
                assert length >= 2
                options = options[length:]
            raise AssertionError('No MSS on captured TCP SYN')
elif sys.argv[1] == 'server':
    threading.Thread(target=udp_server, daemon=True).start()
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 28001))
        sock.listen()
        while True:
            conn, peer = sock.accept()
            threading.Thread(target=tcp_connection, args=(conn,), daemon=True).start()
else:
    host, port = sys.argv[2], int(sys.argv[3])
    selected = sys.argv[4] if len(sys.argv) > 4 else 'both'
    size = int(sys.argv[5]) if len(sys.argv) > 5 else 5
    payload = (b'probe' * ((size+4)//5))[:size]
    for protocol, kind in [('tcp', socket.SOCK_STREAM), ('udp', socket.SOCK_DGRAM)]:
        if selected != 'both' and protocol != selected:
            continue
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.settimeout(4)
            if protocol == 'tcp' and os.environ.get('GTM_TEST_TCP_MSS'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, int(os.environ['GTM_TEST_TCP_MSS']))
            sock.connect((host, port))
            if protocol == 'tcp':
                sock.sendall(len(payload).to_bytes(4, 'big') + payload)
                response = receive_exact(sock, size+4)
            else:
                sock.sendall(payload)
                response = sock.recv(65535)
            assert response == (protocol + ':').encode() + payload
    print(f'PASS: {selected} traffic reached the backend and replies returned.')
