"""Python socket client for the same four peers as bench_tcp.mojo (bench_peer.py must be running).
Prints the Python column of the README table."""
import socket, time
def conn(p):
    s = socket.create_connection(("127.0.0.1", p)); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); return s
G = 1 << 30
s = conn(19401); chunk = bytes(1 << 20); t = time.perf_counter()
for _ in range(G >> 20): s.sendall(chunk)
send = G / (time.perf_counter() - t) / 1e6; s.close()
s = conn(19402); s.sendall(G.to_bytes(8, "big")); got = 0; t = time.perf_counter()
while True:
    b = s.recv(65536)
    if not b: break
    got += len(b)
recv = got / (time.perf_counter() - t) / 1e6; s.close()
s = conn(19403); m = bytes(64); t = time.perf_counter()
for _ in range(20000):
    s.sendall(m); r = 0
    while r < 64: r += len(s.recv(64 - r))
rr = (time.perf_counter() - t) / 20000 * 1e6; s.close()
t = time.perf_counter()
for _ in range(300): c = conn(19404); c.close()
cc = (time.perf_counter() - t) / 300 * 1e6
print(f"py send {send:.0f} MB/s | recv {recv:.0f} MB/s | req/resp {rr:.1f} us | connect {cc:.1f} us")
