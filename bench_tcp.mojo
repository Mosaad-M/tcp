# bench_tcp.mojo — loopback benchmarks against bench_peer.py (pixi run bench)

from std.time import perf_counter_ns
from tcp import TcpSocket, _resolve_all

def mbps(nbytes: Int, ns: Int) -> Float64:
    return Float64(nbytes) / (Float64(ns) / 1e9) / 1e6

def hdr(n: Int) -> List[UInt8]:
    var h = List[UInt8]()
    for i in range(8):
        h.append(UInt8((n >> (8 * (7 - i))) & 0xFF))
    return h^

def main() raises:
    print("tcp benchmarks (loopback; Python client on the same machine: send ~8.3 GB/s, recv ~8.6 GB/s, request/response ~28 us, connect ~109 us)")
    # send_bytes throughput
    var total = 1 << 30
    var chunk = List[UInt8](length=1 << 20, fill=0x41)
    var s = TcpSocket()
    s.connect("127.0.0.1", 19401)
    var t = perf_counter_ns()
    var sent = 0
    while sent < total:
        sent += s.send_bytes(chunk)
    print("tcp     send_bytes 1 GiB (1 MiB):    ", Int(mbps(total, perf_counter_ns() - t)), "MB/s")
    s.close()

    # send(String) throughput
    var str_chunk = String("A") * (1 << 20)
    var s1 = TcpSocket()
    s1.connect("127.0.0.1", 19401)
    t = perf_counter_ns()
    sent = 0
    while sent < total:
        sent += s1.send(str_chunk)
    print("tcp     send(String) 1 GiB (1 MiB):  ", Int(mbps(total, perf_counter_ns() - t)), "MB/s")
    s1.close()

    # recv_bytes throughput
    var s2 = TcpSocket()
    s2.connect("127.0.0.1", 19402)
    _ = s2.send_bytes(hdr(total))
    t = perf_counter_ns()
    var got = 0
    while True:
        var b = s2.recv_bytes(65536)
        if len(b) == 0:
            break
        got += len(b)
    print("tcp     recv_bytes 1 GiB (64 KiB):   ", Int(mbps(got, perf_counter_ns() - t)), "MB/s")

    # recv_all throughput
    var n_all = 256 << 20
    var s3 = TcpSocket()
    s3.connect("127.0.0.1", 19402)
    _ = s3.send_bytes(hdr(n_all))
    t = perf_counter_ns()
    var all = s3.recv_all(max_size=n_all)
    print("tcp     recv_all 256 MiB:            ", Int(mbps(len(all), perf_counter_ns() - t)), "MB/s")

    # recv_bytes_exact, pg-style: 5-byte header + 59-byte body per message
    var n_msgs = 200000
    var s4 = TcpSocket()
    s4.connect("127.0.0.1", 19402)
    _ = s4.send_bytes(hdr(n_msgs * 64))
    t = perf_counter_ns()
    for _ in range(n_msgs):
        _ = s4.recv_bytes_exact(5)
        _ = s4.recv_bytes_exact(59)
    var ns = perf_counter_ns() - t
    print("tcp     recv_bytes_exact 5+59 B:     ", Float64(Int(Float64(ns) / Float64(n_msgs) / 100.0)) / 10.0, "us/message")

    # request/response latency
    var s5 = TcpSocket()
    s5.connect("127.0.0.1", 19403)
    var msg = List[UInt8](length=64, fill=0x42)
    var n_rr = 20000
    t = perf_counter_ns()
    for _ in range(n_rr):
        _ = s5.send_bytes(msg)
        _ = s5.recv_bytes_exact(64)
    print("tcp     request/response 64 B x20k:  ", Float64(Int(Float64(perf_counter_ns() - t) / Float64(n_rr) / 100.0)) / 10.0, "us")
    s5.close()

    # connect + close latency
    var n_c = 300
    t = perf_counter_ns()
    for _ in range(n_c):
        var c = TcpSocket()
        c.connect("127.0.0.1", 19404)
        c.close()
    print("tcp     connect+close x300:          ", Float64(Int(Float64(perf_counter_ns() - t) / Float64(n_c) / 100.0)) / 10.0, "us")

    # resolution only
    t = perf_counter_ns()
    for _ in range(300):
        _ = _resolve_all("127.0.0.1", 80)
    print("tcp     _resolve_all(127.0.0.1) x300:", Float64(Int(Float64(perf_counter_ns() - t) / 300.0 / 100.0)) / 10.0, "us")
    t = perf_counter_ns()
    for _ in range(50):
        _ = _resolve_all("localhost", 80)
    print("tcp     _resolve_all(localhost) x50: ", Float64(Int(Float64(perf_counter_ns() - t) / 50.0 / 100.0)) / 10.0, "us")
