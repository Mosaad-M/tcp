#!/usr/bin/env python3
"""Benchmark peers for bench_tcp.mojo (fast: large buffers, recv_into)."""
#
#  19401 sink: read and discard everything
#  19402 source: send N bytes (first 8 bytes from client = N, big-endian), then close
#  19403 echo-small: echo (for request/response latency)
#  19404 accept-close: accept and close at once (connect latency)
import socket, threading
BUF = bytearray(1 << 20)
CHUNK = bytes(1 << 20)
def serve(port, h):
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port)); ls.listen(512)
    def loop():
        while True:
            c, _ = ls.accept()
            threading.Thread(target=h, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
def sink(c):
    v = memoryview(bytearray(1 << 20))
    while c.recv_into(v): pass
    c.close()
def source(c):
    h = b""
    while len(h) < 8: h += c.recv(8 - len(h))
    n = int.from_bytes(h, "big")
    while n > 0:
        k = min(n, len(CHUNK)); c.sendall(CHUNK[:k]) if k < len(CHUNK) else c.sendall(CHUNK); n -= k
    c.close()
def echo(c):
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            c.sendall(d)
    except OSError: pass
    c.close()
def accept_close(c): c.close()
serve(19401, sink); serve(19402, source); serve(19403, echo); serve(19404, accept_close)
import time
print("ready", flush=True)
while True: time.sleep(3600)
