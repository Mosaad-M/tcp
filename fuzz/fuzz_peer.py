#!/usr/bin/env python3
"""Hostile peer for fuzz_io.mojo. Every connection to 127.0.0.1:19501 gets a
random behaviour (chosen with the seed in argv[1]):

  echo, burst (random-size chunks then close), reset (a few bytes then RST),
  close at once, silent (never reads or writes), half-close (a few bytes then
  shutdown of its write side, keeps reading), flood (8 MiB then close),
  dribble (1 byte per 10 ms), garbage-then-wait.

Runs until killed.
"""
import random
import socket
import struct
import sys
import threading
import time

PORT = 19501


def serve(seed):
    rnd = random.Random(seed)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", PORT))
    ls.listen(128)
    print("fuzz_peer ready", flush=True)
    while True:
        c, _ = ls.accept()
        mode = rnd.randrange(9)
        r2 = random.Random(rnd.randrange(1 << 30))
        threading.Thread(target=handle, args=(c, mode, r2), daemon=True).start()


def handle(c, mode, r):
    try:
        if mode == 0:                                   # echo
            while True:
                d = c.recv(65536)
                if not d:
                    break
                c.sendall(d)
        elif mode == 1:                                 # burst of random chunks
            n = r.randrange(0, 200000)
            data = bytes(r.randrange(256) for _ in range(min(n, 4096))) * (n // 4096 + 1)
            data = data[:n]
            i = 0
            while i < n:
                k = r.choice([1, 2, 7, 100, 4096, 70000])
                c.sendall(data[i:i + k])
                i += k
                if r.random() < 0.05:
                    time.sleep(0.005)
        elif mode == 2:                                 # reset
            c.sendall(b"x" * r.randrange(0, 50))
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        elif mode == 3:                                 # close at once
            pass
        elif mode == 4:                                 # silent
            time.sleep(0.6)
        elif mode == 5:                                 # half-close
            c.sendall(b"y" * r.randrange(0, 100))
            c.shutdown(socket.SHUT_WR)
            while c.recv(65536):
                pass
        elif mode == 6:                                 # flood
            c.sendall(b"z" * (8 << 20))
        elif mode == 7:                                 # dribble
            for _ in range(20):
                c.sendall(b"d")
                time.sleep(0.005)
        else:                                           # garbage, then wait
            c.sendall(bytes(r.randrange(256) for _ in range(r.randrange(1, 300))))
            time.sleep(0.3)
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


serve(int(sys.argv[1]) if len(sys.argv) > 1 else 1)
