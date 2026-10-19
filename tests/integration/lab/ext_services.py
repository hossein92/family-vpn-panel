#!/usr/bin/env python3
"""Stand-in for "the internet" in the disposable lab (stdlib only).

TCP 80   HTTP: '/ip' returns the caller's address, anything else a small page.
TCP 443, 853, 1080, 1194, 1723   accept and close (reachability probes).
UDP 500, 1194, 4500, 51820       echo (reachability probes).
"""
import http.server
import socket
import socketserver
import threading


class Web(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = (self.client_address[0] if self.path == "/ip" else "lab web page").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def tcp_accept(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    while True:
        c, _ = s.accept()
        c.close()


def udp_echo(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        data, addr = s.recvfrom(2048)
        s.sendto(data, addr)


for p in (443, 853, 1080, 1194, 1723):
    threading.Thread(target=tcp_accept, args=(p,), daemon=True).start()
for p in (500, 1194, 4500, 51820):
    threading.Thread(target=udp_echo, args=(p,), daemon=True).start()
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("0.0.0.0", 80), Web).serve_forever()
