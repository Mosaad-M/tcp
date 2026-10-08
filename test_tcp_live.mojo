# test_tcp_live.mojo — real-network checks (pixi run test-tcp-live; not in CI)

from tcp import TcpSocket


def main() raises:
    print("=== TCP live tests ===")
    var s = TcpSocket()
    s.connect("example.com", 80, reject_private_ips=True)
    _ = s.send("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    var resp = s.recv_all()
    if len(resp) < 12 or resp[0] != UInt8(ord("H")):
        raise Error("no HTTP response from example.com")
    print("  PASS: example.com:80 (", len(resp), "bytes)")
    var s6 = TcpSocket()
    try:
        s6.connect("ipv6.google.com", 80)
        print("  PASS: ipv6.google.com:80 (IPv6-only host)")
    except e:
        print("  SKIP: ipv6.google.com (no IPv6 route here):", String(e))
    print("Results: done")
