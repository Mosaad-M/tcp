# ============================================================================
# test_security.mojo — attack-shaped tests for tcp (pixi run test-security)
# ============================================================================
# What a hostile host name, address or peer can do to a program that uses tcp:
# reach an internal address through an odd spelling or an embedded IPv4,
# exhaust descriptors or memory, or hang it. Needs test_peer.py (like
# test_tcp.mojo). fuzz/ runs the same ideas with random input.
# ============================================================================

from std.ffi import external_call
from std.memory.alloc import unsafe_alloc
from tcp import (
    TcpSocket, _addr_v4, _addr_v6, _is_private_addr, SOL_SOCKET, SO_RCVTIMEO,
    SO_SNDTIMEO,
)

comptime ECHO = 19101
comptime SOURCE = 19107
comptime REFUSED = 19199


def _expect_error(err: String, needle: String, what: String) raises:
    if err == "":
        raise Error(what + ": no error raised")
    if err.find(needle) < 0:
        raise Error(what + ": expected '" + needle + "' in: " + err)


def _v6(groups: List[Int]) -> List[UInt8]:
    var out = List[UInt8]()
    for g in groups:
        out.append(UInt8((g >> 8) & 0xFF))
        out.append(UInt8(g & 0xFF))
    return out^


def _blocked6(groups: List[Int]) -> Bool:
    return _is_private_addr(_addr_v6(_v6(groups), 80))


def _blocked4(a: Int, b: Int, c: Int, d: Int) -> Bool:
    return _is_private_addr(_addr_v4(a, b, c, d, 80))


# ── SSRF: addresses ─────────────────────────────────────────────────────────

def test_ipv4_embedded_in_ipv6_is_judged_by_the_ipv4() raises:
    # 127.0.0.1 = 7f00:0001, 10.1.2.3 = 0a01:0203, 8.8.8.8 = 0808:0808
    var loopback: List[List[Int]] = [
        [0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 1],      # ::ffff:127.0.0.1 (mapped)
        [0, 0, 0, 0, 0, 0, 0x7F00, 1],           # ::127.0.0.1 (compatible)
        [0, 0, 0, 0, 0xFFFF, 0, 0x7F00, 1],      # ::ffff:0:127.0.0.1 (translated, 2.2.0)
        [0x64, 0xFF9B, 0, 0, 0, 0, 0x7F00, 1],   # 64:ff9b::127.0.0.1 (NAT64)
        [0x2002, 0x7F00, 1, 0, 0, 0, 0, 0],      # 6to4 of 127.0.0.1
        [0, 0, 0, 0, 0xFFFF, 0, 0x0A01, 0x0203], # translated 10.1.2.3
        [0, 0, 0, 0, 0, 0xFFFF, 0xA9FE, 0xA9FE], # mapped 169.254.169.254 (cloud metadata)
    ]
    for g in loopback:
        if not _blocked6(g):
            raise Error("embedded internal IPv4 allowed: " + String(g[6]) + ":" + String(g[7]))
    var public: List[List[Int]] = [
        [0, 0, 0, 0, 0, 0xFFFF, 0x0808, 0x0808],
        [0, 0, 0, 0, 0xFFFF, 0, 0x0808, 0x0808],
        [0x64, 0xFF9B, 0, 0, 0, 0, 0x0808, 0x0808],
        [0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111],
        [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888],
    ]
    for g in public:
        if _blocked6(g):
            raise Error("public address blocked: " + String(g[0]) + ":" + String(g[7]))


def test_special_purpose_ipv6_ranges_added_in_2_2_0() raises:
    if not _blocked6([0x5F00, 0, 0, 0, 0, 0, 0, 1]):
        raise Error("5f00::/16 (SRv6 SIDs) allowed")
    if _blocked6([0x5FFF, 0, 0, 0, 0, 0, 0, 1]):
        raise Error("5fff:: is outside 5f00::/16 but was blocked")
    if not _blocked6([0x3FFF, 0, 0, 0, 0, 0, 0, 1]) or not _blocked6([0x3FFF, 0x0FFF, 0, 0, 0, 0, 0, 1]):
        raise Error("3fff::/20 (documentation) allowed")
    if _blocked6([0x3FFF, 0x1000, 0, 0, 0, 0, 0, 1]):
        raise Error("3fff:1000:: is outside 3fff::/20 but was blocked")
    if not _blocked6([0x100, 0, 0, 1, 0, 0, 0, 1]):
        raise Error("100:0:0:1::/64 (dummy prefix) allowed")
    if _blocked6([0x100, 0, 0, 2, 0, 0, 0, 1]):
        raise Error("100:0:0:2:: is outside 100:0:0:1::/64 but was blocked")


def test_ipv4_range_edges() raises:
    # one inside and one outside each edge
    var cases: List[List[Int]] = [
        [9, 255, 255, 255, 0], [10, 0, 0, 0, 1], [10, 255, 255, 255, 1], [11, 0, 0, 0, 0],
        [100, 63, 255, 255, 0], [100, 64, 0, 0, 1], [100, 127, 255, 255, 1], [100, 128, 0, 0, 0],
        [126, 255, 255, 255, 0], [127, 0, 0, 1, 1], [128, 0, 0, 0, 0],
        [169, 253, 255, 255, 0], [169, 254, 0, 0, 1], [169, 254, 255, 255, 1], [169, 255, 0, 0, 0],
        [172, 15, 255, 255, 0], [172, 16, 0, 0, 1], [172, 31, 255, 255, 1], [172, 32, 0, 0, 0],
        [192, 167, 255, 255, 0], [192, 168, 0, 0, 1], [192, 168, 255, 255, 1], [192, 169, 0, 0, 0],
        [198, 17, 255, 255, 0], [198, 18, 0, 0, 1], [198, 19, 255, 255, 1], [198, 20, 0, 0, 0],
        [223, 255, 255, 255, 0], [224, 0, 0, 0, 1], [255, 255, 255, 255, 1],
    ]
    for c in cases:
        if _blocked4(c[0], c[1], c[2], c[3]) != (c[4] == 1):
            raise Error("wrong verdict for " + String(c[0]) + "." + String(c[1]) + "." + String(c[2]) + "." + String(c[3]))


# ── SSRF: host spellings that all mean an internal address ──────────────────

def _connect_error(host: String, reject: Bool) -> String:
    var s = TcpSocket()
    try:
        s.connect(host, ECHO, reject, timeout_ms=500)
        s.close()
        return ""
    except e:
        return String(e)


def test_loopback_spellings_blocked_when_asked() raises:
    # Each of these reaches 127.0.0.1 through getaddrinfo (the first check
    # keeps the test honest: without the filter it connects). The filter
    # judges the resolved address, so the spelling cannot matter.
    var spellings = ["127.0.0.1", "127.1", "127.0.1", "0x7f.1", "0x7f000001", "2130706433", "0177.0.0.1", "localhost"]
    var reached = 0
    for h in spellings:
        if _connect_error(h, False) == "":
            reached += 1
            var err = _connect_error(h, True)
            _expect_error(err, "private/reserved", "reject_private_ips with '" + h + "'")
    if reached < 3:
        raise Error("only " + String(reached) + " spellings reach loopback here: the test proves little")
    # a mapped IPv6 spelling must be refused whether or not the system resolves it
    var err = _connect_error("::ffff:127.0.0.1", True)
    if err == "":
        raise Error("::ffff:127.0.0.1 connected with reject_private_ips")


def test_mangled_hosts_never_connect_to_loopback_when_asked() raises:
    var hosts = [
        "127.0.0.1\0.example.com", "127.0.0.1\r\nHost: evil", "127.0.0.1 ", " 127.0.0.1", "127.0.0.1/",
        "127.0.0.1@evil.example", "[127.0.0.1]", "127.0.0.1:80", "\0127.0.0.1", "",
    ]
    for h in hosts:
        var err = _connect_error(h, True)
        if err == "":
            raise Error("host with junk connected with reject_private_ips: '" + h + "'")
        if not (err.startswith("tcp:") or err.startswith("connection to private")):
            raise Error("unexpected error for junk host: " + err)


def test_long_host_is_an_error_not_a_crash() raises:
    var err = _connect_error(String("a") * 100000, False)
    if err == "":
        raise Error("a 100000-byte host name connected")


# ── Resources ───────────────────────────────────────────────────────────────

def _next_fd() raises -> Int32:
    var s = TcpSocket()
    s.connect("127.0.0.1", ECHO)
    var f = s.fd
    s.close()
    return f


def _churn(n: Int):
    """n failed or refused connects of every kind."""
    for _ in range(n):
        _ = _connect_error("127.0.0.1", False)          # succeeds
    for _ in range(n):
        var s = TcpSocket()
        try:
            s.connect("127.0.0.1", REFUSED, timeout_ms=200)
        except e:
            pass
    for _ in range(n):
        _ = _connect_error("127.1", True)               # SSRF refusal
    for _ in range(n):
        var s = TcpSocket()
        try:
            s.connect("10.255.255.1", 80, timeout_ms=5)  # timeout
        except e:
            pass
    for _ in range(n):
        var s = TcpSocket()
        try:
            s.connect("127.0.0.1", 70000)                # bad port
        except e:
            pass
    for _ in range(n):
        _ = _connect_error("no-such-host.invalid", False)  # DNS failure


def test_failed_connects_leak_no_descriptor() raises:
    # The resolver keeps a few descriptors open for good after its first uses:
    # one round of everything warms it up, then the number must not move.
    _churn(5)
    var base = _next_fd()
    _churn(50)
    var after = _next_fd()
    if after != base:
        raise Error("descriptor " + String(base) + " before 300 failed connects, " + String(after) + " after")


def test_recv_all_stops_at_its_cap() raises:
    # SOURCE sends N bytes on request: the cap must stop the read, not memory
    var s = TcpSocket()
    s.connect("127.0.0.1", SOURCE, timeout_secs=20)
    var n = 8 << 20
    var hdr = List[UInt8]()
    for i in range(8):
        hdr.append(UInt8((n >> (8 * (7 - i))) & 0xFF))
    _ = s.send_bytes(hdr)
    var err = String("")
    try:
        _ = s.recv_all(1 << 20)
    except e:
        err = String(e)
    _expect_error(err, "exceeds maximum size", "recv_all past its cap")


# ── Timeouts reach the kernel ───────────────────────────────────────────────

def _timeout_us(fd: Int32, opt: Int32) raises -> Int:
    var tv = unsafe_alloc[UInt8](16)
    for i in range(16):
        tv[unsafe_offset=i] = 0
    var n = unsafe_alloc[Int32](1)
    n[unsafe_offset=0] = 16
    var rc = external_call["getsockopt", Int32](fd, SOL_SOCKET, opt, Int(tv), Int(n))
    var w = tv.unsafe_bitcast[Int]()
    var us = w[unsafe_offset=0] * 1_000_000 + (w[unsafe_offset=1] & 0xFFFFFFFF)
    tv.unsafe_free()
    n.unsafe_free()
    if rc != 0:
        raise Error("getsockopt failed")
    return us


def test_timeout_values_reach_the_kernel() raises:
    var s = TcpSocket()
    s.connect("127.0.0.1", ECHO)
    for ms in [1, 5, 250, 999, 1000, 1001, 1500, 59999, 3_600_000]:
        s.set_timeout_ms(ms)
        for opt in [SO_RCVTIMEO, SO_SNDTIMEO]:
            var got = _timeout_us(s.fd, opt)
            if got < ms * 1000 or got - ms * 1000 > 20_000:
                raise Error("set_timeout_ms(" + String(ms) + "): kernel holds " + String(got) + " us")
    s.set_timeout(7)
    if abs(_timeout_us(s.fd, SO_RCVTIMEO) - 7_000_000) > 20_000:
        raise Error("set_timeout(7) wrong")
    s.set_timeout_ms(0)
    if _timeout_us(s.fd, SO_RCVTIMEO) != 0:
        raise Error("set_timeout_ms(0) is not 'no timeout'")
    # huge values clamp; they do not wrap into a short or negative timeout
    s.set_timeout_ms(10**18)
    s.set_timeout(10**18)
    if _timeout_us(s.fd, SO_RCVTIMEO) < 1_000_000_000:
        raise Error("a huge timeout wrapped into a short one")
    s.close()


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
    print("=== tcp security tests ===")
    run_test[test_ipv4_embedded_in_ipv6_is_judged_by_the_ipv4]("embedded IPv4 (mapped, compatible, translated, NAT64, 6to4) is judged by the IPv4", passed, failed)
    run_test[test_special_purpose_ipv6_ranges_added_in_2_2_0]("5f00::/16, 3fff::/20 and 100:0:0:1::/64 blocked, neighbours not", passed, failed)
    run_test[test_ipv4_range_edges]("IPv4 range edges: one inside, one outside", passed, failed)
    run_test[test_loopback_spellings_blocked_when_asked]("loopback spellings (127.1, 0x7f.1, 2130706433, ...) blocked", passed, failed)
    run_test[test_mangled_hosts_never_connect_to_loopback_when_asked]("NUL / CRLF / junk in a loopback host never connects", passed, failed)
    run_test[test_long_host_is_an_error_not_a_crash]("100000-byte host name is an error", passed, failed)
    run_test[test_failed_connects_leak_no_descriptor]("300 failed connects leak no descriptor", passed, failed)
    run_test[test_recv_all_stops_at_its_cap]("recv_all stops at its cap", passed, failed)
    run_test[test_timeout_values_reach_the_kernel]("timeouts reach the kernel (read back with getsockopt)", passed, failed)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
