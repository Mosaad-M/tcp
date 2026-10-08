# ============================================================================
# test_tcp.mojo — tcp against local peers (test_peer.py; pixi run test-tcp)
# ============================================================================
# Each 1.1.0 defect found in the October 2026 deep dive has a test here:
# SIGPIPE on a closed peer, silent short sends, SSRF ranges, the connect
# timeout on macOS, IPv4-only / first-address-only connects, leaked fds,
# reason-less errors, recv_bytes(0), port validation.
# ============================================================================

from std.ffi import external_call
from std.memory import alloc
from std.time import perf_counter_ns
from tcp import (
    TcpSocket, _Addr, _addr_v4, _addr_v6, _format_addr,
    _is_private_ip, _is_private_ip6, _poll_ms,
)

comptime ECHO = 19101
comptime CLOSE = 19102
comptime SILENT = 19103
comptime SLOW = 19104
comptime ECHO6 = 19105
comptime GREET = 19106
comptime SOURCE = 19107
comptime REQRESP = 19108
comptime REFUSED = 19199


def _ms_since(t: Int) -> Int:
    return (perf_counter_ns() - t) // 1_000_000


def _sleep_ms(ms: Int):
    var t = perf_counter_ns()
    while _ms_since(t) < ms:
        pass


def _expect_error(err: String, needle: String, what: String) raises:
    if err == "":
        raise Error(what + ": no error raised")
    if err.find(needle) < 0:
        raise Error(what + ": expected '" + needle + "' in: " + err)


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def _v4(a: Int, b: Int, c: Int, d: Int) -> UInt32:
    """IPv4 address as stored in sin_addr (network order, little-endian host)."""
    return UInt32(a) | (UInt32(b) << 8) | (UInt32(c) << 16) | (UInt32(d) << 24)


def _v6(groups: List[Int]) -> List[UInt8]:
    """16 bytes from 8 groups (no :: compression here)."""
    var out = List[UInt8]()
    for g in groups:
        out.append(UInt8((g >> 8) & 0xFF))
        out.append(UInt8(g & 0xFF))
    return out^


# ── Data paths ──────────────────────────────────────────────────────────────

def test_echo_round_trip() raises:
    var s = TcpSocket()
    s.connect("127.0.0.1", ECHO)
    if s.send("ping") != 4:
        raise Error("send(String) did not report 4 bytes")
    var payload = List[UInt8](length=100000, fill=0x5A)
    if s.send_bytes(payload) != len(payload):
        raise Error("send_bytes did not report the full length")
    var back = s.recv_bytes_exact(4 + len(payload))
    if back[0] != UInt8(ord("p")) or back[len(back) - 1] != 0x5A:
        raise Error("echo mismatch")
    s.close()


def test_recv_all_until_close() raises:
    var s = TcpSocket()
    s.connect("127.0.0.1", GREET)
    var got = s.recv_all()
    if String(unsafe_from_utf8=got^) != "hello":
        raise Error("recv_all did not return the greeting")


def test_send_completes_to_slow_reader() raises:
    # 1.1.0 returned a short count from one send() call; callers dropped it
    var n = 8 * 1024 * 1024
    var s = TcpSocket()
    s.connect("127.0.0.1", SLOW, timeout_secs=10)
    var data = List[UInt8](capacity=8 + n)
    for i in range(8):
        data.append(UInt8((n >> (8 * (7 - i))) & 0xFF))
    for _ in range(n):
        data.append(0x42)
    if s.send_bytes(data) != len(data):
        raise Error("send_bytes returned a short count")
    var reply = String(unsafe_from_utf8=s.recv_bytes(32)^)
    if reply != String(n):
        raise Error("peer received " + reply + " of " + String(n) + " bytes")


def test_send_timeout_raises() raises:
    # 1.1.0: send() of 64 MiB to a peer that never reads returned ~1.8 MB, no error
    var s = TcpSocket()
    s.connect("127.0.0.1", SILENT, timeout_secs=1)
    var err = String("")
    try:
        _ = s.send_bytes(List[UInt8](length=64 * 1024 * 1024, fill=0x43))
    except e:
        err = String(e)
    _expect_error(err, "send timed out", "send to a peer that never reads")


def test_recv_timeout_message() raises:
    var s = TcpSocket()
    s.connect("127.0.0.1", SILENT, timeout_secs=1)
    var t = perf_counter_ns()
    var err = String("")
    try:
        _ = s.recv_bytes(100)
    except e:
        err = String(e)
    _expect_error(err, "recv timed out", "recv from a silent peer")
    if _ms_since(t) > 3000:
        raise Error("recv timeout took " + String(_ms_since(t)) + " ms")


def test_closed_peer_no_sigpipe() raises:
    # 1.1.0: the process was killed by SIGPIPE (exit 141) on the second send
    var s = TcpSocket()
    s.connect("127.0.0.1", CLOSE)
    var err = String("")
    for _ in range(10):
        _sleep_ms(100)
        try:
            _ = s.send("x" * 1000)
        except e:
            err = String(e)
            break
    _expect_error(err, "closed by peer", "send to a closed peer")


# ── Connecting ──────────────────────────────────────────────────────────────

def test_connect_refused_reason() raises:
    var s = TcpSocket()
    var err = String("")
    try:
        s.connect("127.0.0.1", REFUSED)
    except e:
        err = String(e)
    _expect_error(err, "127.0.0.1", "refused connect")
    _expect_error(err, "refused", "refused connect")


def test_connect_timeout_honored() raises:
    # 1.1.0 on macOS: 75 s for timeout_secs=2. Some networks reject the
    # address at once (unreachable), which is also fine.
    var s = TcpSocket()
    var t = perf_counter_ns()
    var err = String("")
    try:
        s.connect("10.255.255.1", 80, timeout_secs=2)
    except e:
        err = String(e)
    if err == "":
        raise Error("connected to 10.255.255.1?")
    if _ms_since(t) > 6000:
        raise Error("connect took " + String(_ms_since(t)) + " ms with timeout_secs=2")


def test_connect_ipv6_loopback() raises:
    var s = TcpSocket()
    s.connect("::1", ECHO6)
    _ = s.send("v6")
    var back = s.recv_bytes_exact(2)
    if back[0] != UInt8(ord("v")):
        raise Error("IPv6 echo mismatch")


def test_fallback_to_next_address() raises:
    # A host whose first address refuses: 1.1.0 tried only the first one
    var addrs = List[_Addr]()
    addrs.append(_addr_v4(127, 0, 0, 1, REFUSED))
    addrs.append(_addr_v6(_v6([0, 0, 0, 0, 0, 0, 0, 1]), ECHO6))
    var s = TcpSocket()
    s._connect_addrs(addrs, "dual.test", ECHO6, False, 5)
    _ = s.send("ok")
    _ = s.recv_bytes_exact(2)


def test_dns_error_reason() raises:
    var s = TcpSocket()
    var err = String("")
    try:
        s.connect("no-such-host-for-tcp-tests.invalid", 80)
    except e:
        err = String(e)
    _expect_error(err, "cannot resolve no-such-host-for-tcp-tests.invalid", "DNS failure")
    if err.find("error 8)") >= 0:
        raise Error("bare getaddrinfo code: " + err)


def test_port_validation() raises:
    for port in [0, 65536, -1]:
        var s = TcpSocket()
        var err = String("")
        try:
            s.connect("127.0.0.1", port)
        except e:
            err = String(e)
        _expect_error(err, "port", "port " + String(port))


def test_recv_bytes_zero_raises() raises:
    var s = TcpSocket()
    s.connect("127.0.0.1", ECHO)
    var err = String("")
    try:
        _ = s.recv_bytes(0)
    except e:
        err = String(e)
    _expect_error(err, "max_bytes", "recv_bytes(0)")


# ── SSRF ────────────────────────────────────────────────────────────────────

def test_ssrf_ipv4_ranges() raises:
    var blocked = [
        _v4(0, 1, 2, 3), _v4(10, 0, 0, 1), _v4(100, 64, 0, 1), _v4(100, 127, 255, 254),
        _v4(127, 0, 0, 1), _v4(169, 254, 169, 254), _v4(172, 16, 0, 1), _v4(172, 31, 255, 255),
        _v4(192, 0, 0, 170), _v4(192, 0, 2, 1), _v4(192, 88, 99, 1), _v4(192, 168, 1, 1),
        _v4(198, 18, 0, 1), _v4(198, 19, 255, 255), _v4(198, 51, 100, 7), _v4(203, 0, 113, 9),
        _v4(224, 0, 0, 1), _v4(239, 255, 255, 250), _v4(240, 0, 0, 1), _v4(255, 255, 255, 255),
    ]
    var allowed = [
        _v4(1, 1, 1, 1), _v4(8, 8, 8, 8), _v4(100, 63, 255, 255), _v4(100, 128, 0, 0),
        _v4(172, 15, 0, 1), _v4(172, 32, 0, 1), _v4(192, 0, 1, 1), _v4(198, 17, 0, 1),
        _v4(198, 20, 0, 1), _v4(223, 255, 255, 255), _v4(93, 184, 216, 34),
    ]
    for a in blocked:
        if not _is_private_ip(a):
            raise Error("not blocked: " + _format_addr(_addr_v4(Int(a & 0xFF), Int((a >> 8) & 0xFF), Int((a >> 16) & 0xFF), Int(a >> 24), 1)))
    for a in allowed:
        if _is_private_ip(a):
            raise Error("blocked: " + _format_addr(_addr_v4(Int(a & 0xFF), Int((a >> 8) & 0xFF), Int((a >> 16) & 0xFF), Int(a >> 24), 1)))


def test_ssrf_ipv6_ranges() raises:
    var blocked = List[List[Int]]()
    blocked.append([0, 0, 0, 0, 0, 0, 0, 0])                     # ::
    blocked.append([0, 0, 0, 0, 0, 0, 0, 1])                     # ::1
    blocked.append([0xFC00, 0, 0, 0, 0, 0, 0, 1])                # ULA
    blocked.append([0xFD12, 0x3456, 0, 0, 0, 0, 0, 1])           # ULA
    blocked.append([0xFE80, 0, 0, 0, 0, 0, 0, 1])                # link-local
    blocked.append([0xFEC0, 0, 0, 0, 0, 0, 0, 1])                # site-local
    blocked.append([0xFF02, 0, 0, 0, 0, 0, 0, 1])                # multicast
    blocked.append([0x0100, 0, 0, 0, 0, 0, 0, 1])                # discard
    blocked.append([0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1])           # documentation
    blocked.append([0x2001, 0x0000, 0x4136, 0, 0, 0, 0, 1])      # Teredo
    blocked.append([0x0064, 0xFF9B, 0x0001, 0, 0, 0, 0, 1])      # local NAT64
    blocked.append([0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001])      # ::ffff:127.0.0.1
    blocked.append([0, 0, 0, 0, 0, 0xFFFF, 0xA9FE, 0xA9FE])      # ::ffff:169.254.169.254
    blocked.append([0x0064, 0xFF9B, 0, 0, 0, 0, 0x0A00, 0x0001]) # NAT64 of 10.0.0.1
    blocked.append([0x2002, 0xC0A8, 0x0101, 0, 0, 0, 0, 1])      # 6to4 of 192.168.1.1
    var allowed = List[List[Int]]()
    allowed.append([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111]) # 2606:4700:4700::1111
    allowed.append([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888]) # Google DNS
    allowed.append([0, 0, 0, 0, 0, 0xFFFF, 0x0808, 0x0808])      # ::ffff:8.8.8.8
    allowed.append([0x0064, 0xFF9B, 0, 0, 0, 0, 0x0808, 0x0808]) # NAT64 of 8.8.8.8
    allowed.append([0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 1])      # 6to4 of 8.8.8.8
    for g in blocked:
        if not _is_private_ip6(_v6(g)):
            raise Error("not blocked: " + _format_addr(_addr_v6(_v6(g), 1)))
    for g in allowed:
        if _is_private_ip6(_v6(g)):
            raise Error("blocked: " + _format_addr(_addr_v6(_v6(g), 1)))


def test_reject_private_ips_both_families() raises:
    for host in ["127.0.0.1", "::1"]:
        var s = TcpSocket()
        var err = String("")
        try:
            s.connect(host, ECHO, reject_private_ips=True)
        except e:
            err = String(e)
        _expect_error(err, "SSRF", "reject_private_ips for " + host)


def test_address_formatting() raises:
    if _format_addr(_addr_v4(93, 184, 216, 34, 80)) != "93.184.216.34":
        raise Error("v4: " + _format_addr(_addr_v4(93, 184, 216, 34, 80)))
    var v6 = _format_addr(_addr_v6(_v6([0x2606, 0x2800, 0, 0, 0, 0, 0, 1]), 80))
    if v6 != "[2606:2800:0:0:0:0:0:1]":
        raise Error("v6: " + v6)


# ── Ownership ───────────────────────────────────────────────────────────────

def test_reconnect_does_not_leak() raises:
    var s = TcpSocket()
    s.connect("127.0.0.1", ECHO)
    var first = s.fd
    for _ in range(50):
        s.connect("127.0.0.1", ECHO)
    if s.fd != first:
        raise Error("fd grew from " + String(first) + " to " + String(s.fd) + " (leak)")


def test_dropped_sockets_are_closed() raises:
    var first = Int32(-1)
    var last = Int32(-1)
    for i in range(50):
        var s = TcpSocket()
        s.connect("127.0.0.1", ECHO)
        if i == 0:
            first = s.fd
        last = s.fd
    if last != first:
        raise Error("fd grew from " + String(first) + " to " + String(last) + " (leak)")


def _owned_fd() raises -> Int32:
    var s = TcpSocket()
    s.connect("127.0.0.1", ECHO)
    return s.detach()   # s is destroyed here; the fd must stay open


def test_detach_keeps_fd_open() raises:
    var fd = _owned_fd()
    var buf = alloc[UInt8](2)
    buf[unsafe_offset=0] = UInt8(ord("h"))
    buf[unsafe_offset=1] = UInt8(ord("i"))
    var sent = external_call["send", Int](fd, Int(buf), 2, Int32(0))
    var got = 0
    var t = perf_counter_ns()
    while got < 2 and _ms_since(t) < 3000:
        var n = external_call["recv", Int](fd, Int(buf.unsafe_offset(got)), 2 - got, Int32(0))
        if n <= 0:
            break
        got += n
    buf.unsafe_free()
    _ = external_call["close", Int32](fd)
    if sent != 2 or got != 2:
        raise Error("detached fd unusable (sent " + String(sent) + ", got " + String(got) + ")")


# ── 2.0.1: bounded allocations, large transfers, connect deadline ───────────

def _source(n: Int) raises -> TcpSocket:
    var s = TcpSocket()
    s.connect("127.0.0.1", SOURCE, timeout_secs=20)
    var h = List[UInt8]()
    for i in range(8):
        h.append(UInt8((n >> (8 * (7 - i))) & 0xFF))
    _ = s.send_bytes(h)
    return s^


def _check_pattern(data: List[UInt8], n: Int, what: String) raises:
    if len(data) != n:
        raise Error(what + ": got " + String(len(data)) + " of " + String(n) + " bytes")
    for i in range(n):
        if data[i] != UInt8(i % 251):
            raise Error(what + ": wrong byte at offset " + String(i))


def test_recv_all_large_correct() raises:
    var n = 32 * 1024 * 1024 + 12345
    var s = _source(n)
    _check_pattern(s.recv_all(), n, "recv_all")


def test_recv_bytes_exact_large_correct() raises:
    var n = 8 * 1024 * 1024 + 7
    var s = _source(n)
    _check_pattern(s.recv_bytes_exact(n), n, "recv_bytes_exact")


def test_recv_bytes_exact_huge_n() raises:
    # 2.0.0 reserved all n bytes up front and passed n to recv(): EINVAL
    var s = TcpSocket()
    s.connect("127.0.0.1", GREET)
    var err = String("")
    try:
        _ = s.recv_bytes_exact(1 << 40)
    except e:
        err = String(e)
    _expect_error(err, "closed after 5 of", "recv_bytes_exact(1 TiB) from a 5-byte peer")


def test_recv_bytes_huge_max() raises:
    var s = TcpSocket()
    s.connect("127.0.0.1", GREET)
    var got = s.recv_bytes(1 << 40)
    if len(got) == 0 or len(got) > 5:
        raise Error("recv_bytes(1 TiB) returned " + String(len(got)) + " bytes")


def test_connect_deadline_total() raises:
    # 2.0.0 gave each address the full timeout: 8 addresses x 2 s = 16 s
    var addrs = List[_Addr]()
    for i in range(8):
        addrs.append(_addr_v4(10, 255, 255, i + 1, 80))
    var s = TcpSocket()
    var t = perf_counter_ns()
    var err = String("")
    try:
        s._connect_addrs(addrs, "many.test", 80, False, 2)
    except e:
        err = String(e)
    if err == "":
        raise Error("connected to an unroutable address?")
    if _ms_since(t) > 3500:
        raise Error("8 addresses took " + String(_ms_since(t)) + " ms with timeout_secs=2")


def test_poll_timeout_clamped() raises:
    if _poll_ms(10**12) != Int32.MAX:
        raise Error("_poll_ms(10**12) = " + String(_poll_ms(10**12)))
    if _poll_ms(0) != -1 or _poll_ms(1500) != 1500:
        raise Error("_poll_ms(0) / _poll_ms(1500) wrong")


# ── 2.0.2: TCP_NODELAY, peer_closed() ───────────────────────────────────────

def _nodelay_of(fd: Int32) raises -> Int32:
    """getsockopt(IPPROTO_TCP=6, TCP_NODELAY=1), declared as tcp declares it."""
    var val = alloc[Int32](2)
    val[unsafe_offset=0] = -1
    val[unsafe_offset=1] = 4
    var rc = external_call["getsockopt", Int32](fd, Int32(6), Int32(1), Int(val), Int(val.unsafe_offset(1)))
    var v = val[unsafe_offset=0]
    val.unsafe_free()
    if rc != 0:
        raise Error("getsockopt(TCP_NODELAY) failed on fd " + String(fd))
    return v


def test_nodelay_default_and_opt_out() raises:
    var s = TcpSocket()
    s.connect("127.0.0.1", ECHO)
    if _nodelay_of(s.fd) == 0:
        raise Error("TCP_NODELAY not set by default")
    var t = TcpSocket()
    t.connect("127.0.0.1", ECHO, nodelay=False)
    if _nodelay_of(t.fd) != 0:
        raise Error("TCP_NODELAY set although nodelay=False")
    # Keep both alive until here: a TcpSocket is destroyed (and its fd
    # closed) right after its last use, which would be the .fd read above
    s.close()
    t.close()


def test_peer_closed_open_socket() raises:
    var s = TcpSocket()
    s.connect("127.0.0.1", ECHO)
    if s.peer_closed():
        raise Error("fresh connection reported closed")
    _ = s.send("ping")
    var t = perf_counter_ns()
    while _ms_since(t) < 300:
        pass
    if s.peer_closed():
        raise Error("connection with pending data reported closed")
    var back = s.recv_bytes_exact(4)   # the peek must not consume
    if back[0] != UInt8(ord("p")):
        raise Error("peek consumed data")


def test_peer_closed_after_close() raises:
    var s = TcpSocket()
    s.connect("127.0.0.1", CLOSE)
    var t = perf_counter_ns()
    while not s.peer_closed():
        if _ms_since(t) > 2000:
            raise Error("closed peer not detected within 2 s")
    var u = TcpSocket()
    if not u.peer_closed():
        raise Error("unconnected socket not reported closed")


def test_small_writes_latency() raises:
    """Informational: a request sent in 5 small writes, then the reply.
    reqresp answers once per whole request (PostgreSQL, HTTP); echo answers
    every segment with its own small write (a peer without TCP_NODELAY)."""
    for port in [REQRESP, ECHO]:
        for nd in [True, False]:
            var s = TcpSocket()
            s.connect("127.0.0.1", port, nodelay=nd)
            var t = perf_counter_ns()
            for _ in range(100):
                for _ in range(5):
                    _ = s.send("abcd")
                _ = s.recv_bytes_exact(4 if port == REQRESP else 20)
            var label = "request/response peer" if port == REQRESP else "echo peer"
            print("    " + label + ", 5 writes + reply, nodelay=" + String(nd) + ":", (perf_counter_ns() - t) // 100 // 1000, "us")


# ── Runner ──────────────────────────────────────────────────────────────────

def run_test[test_fn: def() thin raises -> None](
    name: String,
    mut passed: Int,
    mut failed: Int,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


def main() raises:
    var passed = 0
    var failed = 0
    print("=== TCP Socket Tests (local peers) ===")
    run_test[test_echo_round_trip]("echo round trip: send, send_bytes, recv_bytes_exact", passed, failed)
    run_test[test_recv_all_until_close]("recv_all until the peer closes", passed, failed)
    run_test[test_send_completes_to_slow_reader]("8 MiB to a slow reader arrives completely", passed, failed)
    run_test[test_send_timeout_raises]("send to a peer that never reads raises 'send timed out'", passed, failed)
    run_test[test_recv_timeout_message]("recv timeout raises 'recv timed out'", passed, failed)
    run_test[test_closed_peer_no_sigpipe]("send to a closed peer raises (no SIGPIPE)", passed, failed)
    run_test[test_connect_refused_reason]("refused connect names the address and reason", passed, failed)
    run_test[test_connect_timeout_honored]("connect timeout honored (unroutable address)", passed, failed)
    run_test[test_connect_ipv6_loopback]("IPv6 connect to ::1", passed, failed)
    run_test[test_fallback_to_next_address]("falls back to the next address", passed, failed)
    run_test[test_dns_error_reason]("DNS failure has a readable reason", passed, failed)
    run_test[test_port_validation]("ports outside 1-65535 rejected", passed, failed)
    run_test[test_recv_bytes_zero_raises]("recv_bytes(0) raises", passed, failed)
    run_test[test_ssrf_ipv4_ranges]("SSRF: IPv4 special-purpose ranges", passed, failed)
    run_test[test_ssrf_ipv6_ranges]("SSRF: IPv6 ranges and embedded IPv4", passed, failed)
    run_test[test_reject_private_ips_both_families]("reject_private_ips blocks 127.0.0.1 and ::1", passed, failed)
    run_test[test_address_formatting]("address formatting", passed, failed)
    run_test[test_reconnect_does_not_leak]("connect() twice closes the first socket", passed, failed)
    run_test[test_dropped_sockets_are_closed]("dropped sockets are closed", passed, failed)
    run_test[test_detach_keeps_fd_open]("detach() hands over an open fd", passed, failed)
    run_test[test_recv_all_large_correct]("recv_all: 32 MiB arrives intact", passed, failed)
    run_test[test_recv_bytes_exact_large_correct]("recv_bytes_exact: 8 MiB arrives intact", passed, failed)
    run_test[test_recv_bytes_exact_huge_n]("recv_bytes_exact(1 TiB) does not reserve or EINVAL", passed, failed)
    run_test[test_recv_bytes_huge_max]("recv_bytes(1 TiB) returns what is available", passed, failed)
    run_test[test_connect_deadline_total]("timeout bounds the whole connect (8 addresses)", passed, failed)
    run_test[test_poll_timeout_clamped]("poll timeout clamped to Int32", passed, failed)
    run_test[test_nodelay_default_and_opt_out]("TCP_NODELAY by default; nodelay=False opts out", passed, failed)
    run_test[test_peer_closed_open_socket]("peer_closed(): open socket, peek keeps data", passed, failed)
    run_test[test_peer_closed_after_close]("peer_closed(): closed peer and unconnected socket", passed, failed)
    run_test[test_small_writes_latency]("small-writes latency (informational)", passed, failed)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
