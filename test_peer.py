#!/usr/bin/env python3
"""Local peers for test_tcp.mojo: one listening port per behavior.

  19101 echo        echoes everything back
  19102 close       accepts, then closes at once (later writes get EPIPE/RST)
  19103 silent      accepts, never reads or writes (send/recv timeouts)
  19104 slow        reads an 8-byte big-endian length N, waits 1 s, reads N
                    bytes, replies with the count in decimal
  19105 echo6       echo on [::1] (IPv6)
  19106 greet       sends "hello" and closes (recv_all / end of stream)
  19107 source      reads an 8-byte big-endian length N, sends N bytes of the
                    pattern (i % 251) and closes

Nothing listens on 19199 (connection refused). Runs until killed.
"""
import socket
import threading
import time


def serve(port, handler, family=socket.AF_INET, host="127.0.0.1"):
    ls = socket.socket(family, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((host, port))
    ls.listen(64)

    def loop():
        while True:
            c, _ = ls.accept()
            threading.Thread(target=handler, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def echo(c):
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(d)
    except OSError:
        pass
    c.close()


def close_now(c):
    c.close()


def silent(c):
    time.sleep(60)
    c.close()


def slow(c):
    try:
        hdr = b""
        while len(hdr) < 8:
            hdr += c.recv(8 - len(hdr))
        n = int.from_bytes(hdr, "big")
        time.sleep(1)
        got = 0
        while got < n:
            d = c.recv(min(65536, n - got))
            if not d:
                break
            got += len(d)
        c.sendall(str(got).encode())
    except OSError:
        pass
    c.close()


PATTERN = bytes(i % 251 for i in range(251 * 4096))


def source(c):
    try:
        hdr = b""
        while len(hdr) < 8:
            hdr += c.recv(8 - len(hdr))
        n = int.from_bytes(hdr, "big")
        off = 0
        while off < n:
            k = min(n - off, len(PATTERN) - (off % 251))
            start = off % 251
            c.sendall(PATTERN[start:start + k])
            off += k
    except OSError:
        pass
    c.close()


def greet(c):
    c.sendall(b"hello")
    c.close()


serve(19101, echo)
serve(19102, close_now)
serve(19103, silent)
serve(19104, slow)
serve(19105, echo, socket.AF_INET6, "::1")
serve(19106, greet)
serve(19107, source)
print("test_peer ready", flush=True)
while True:
    time.sleep(3600)
