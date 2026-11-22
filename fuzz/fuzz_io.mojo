# fuzz_io.mojo — every public TcpSocket operation, with random and extreme
# arguments, against a hostile peer (fuzz_peer.py, port 19501).
#
# A crash (abort, memory fault, hang) fails the run. So does a broken
# invariant:
#   * an error that does not start with "tcp:" (or the SSRF refusal text)
#   * recv_bytes returning more than asked (or 1 MiB), recv_bytes_exact not
#     returning exactly n, recv_all far above max_size, poll_fds returning a
#     different number of results than fds
#   * set_timeout_ms not reaching the socket: SO_RCVTIMEO / SO_SNDTIMEO read
#     back with getsockopt must equal the request (within the kernel tick)
#   * connect(reject_private_ips=True) succeeding to a loopback address, in
#     any spelling of the host (the peer listens on 127.0.0.1)
#   * a leaked descriptor: every socket is closed at the end of an iteration,
#     so the next connect must get the (lowest free) descriptor number it got
#     before. The resolver keeps a few descriptors open for good after the
#     first lookups, so the run starts with a warm-up and allows no more than
#     2 above that baseline (a leak climbs with the iterations)
#
# Usage: fuzz_io <iterations> <seed> [trace]

from std.sys import argv
from std.ffi import external_call
from std.memory.alloc import unsafe_alloc
from tcp import (
    TcpSocket, poll_fds, set_socket_timeout_ms, POLLIN, POLLOUT, POLLERR,
    POLLHUP, SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO,
)

comptime PEER = 19501


struct Rng(Movable):
    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed if seed != 0 else UInt64(88172645463325252)

    def next(mut self) -> Int:
        self.s ^= self.s << 13
        self.s ^= self.s >> 7
        self.s ^= self.s << 17
        return Int(self.s >> 1)

    def below(mut self, n: Int) -> Int:
        return self.next() % n


def _pick(mut r: Rng, vals: List[Int]) -> Int:
    return vals[r.below(len(vals))]


def _ms(mut r: Rng) -> Int:
    """A timeout in ms: mostly short (the run has to finish), sometimes extreme."""
    var k = r.below(12)
    if k < 6:
        return _pick(r, [1, 2, 5, 10, 20, 50, 100, 150])
    if k < 8:
        return r.below(1000)
    if k == 8:
        return _pick(r, [999, 1000, 1001, 1500, 59999, 60000, 86400000])
    if k == 9:
        return _pick(r, [2147483647, 2147483648, 10**12, 10**15, 10**18])
    if k == 10:
        return _pick(r, [-1, -1000, -(10**18)])
    return 0


def _read_timeout_us(fd: Int32, opt: Int32) raises -> Int:
    """SO_RCVTIMEO / SO_SNDTIMEO as microseconds (struct timeval)."""
    var tv = unsafe_alloc[UInt8](16)
    for i in range(16):
        tv[unsafe_offset=i] = 0
    var n = unsafe_alloc[Int32](1)
    n[unsafe_offset=0] = 16
    var rc = external_call["getsockopt", Int32](fd, SOL_SOCKET, opt, Int(tv), Int(n))
    var w = tv.unsafe_bitcast[Int]()
    var sec = w[unsafe_offset=0]
    var usec = w[unsafe_offset=1] & 0xFFFFFFFF
    tv.unsafe_free()
    n.unsafe_free()
    if rc != 0:
        raise Error("getsockopt failed")
    return sec * 1_000_000 + usec


def _tcp_error(e: Error, what: String) raises:
    var m = String(e)
    # the SSRF refusal has always read "connection to private/reserved IP address blocked ..."
    if not m.startswith("tcp:") and not m.startswith("connection to private/reserved IP address blocked"):
        raise Error("VIOLATION: " + what + " raised a non-tcp error: " + m)


def _check_timeouts(s: TcpSocket, ms: Int, what: String) raises:
    """What the kernel holds must be what was asked, up to its clock tick."""
    if ms > 1_000_000_000 or ms < 0:
        return
    var want = ms * 1000
    for opt in [SO_RCVTIMEO, SO_SNDTIMEO]:
        var got = _read_timeout_us(s.fd, opt)
        if got < want or got - want > 20_000:
            raise Error(
                "VIOLATION: " + what + ": asked " + String(ms) + " ms, kernel holds " + String(got) + " us"
            )


def _short_again(s: TcpSocket) raises:
    """0 and huge timeouts mean "wait for ever", which would hang the run on a
    peer that never answers: after the read-back they are replaced."""
    s.set_timeout_ms(100)


def _host(mut r: Rng) -> String:
    """A spelling of a loopback address, sometimes mangled."""
    var bases = [
        "127.0.0.1", "127.1", "127.0.1", "0x7f.1", "0x7f000001", "2130706433", "017700000001",
        "0177.0.0.1", "localhost", "LOCALHOST", "::1", "[::1]", "::ffff:127.0.0.1", "::ffff:7f00:1",
        "0.0.0.0", "0", "127.0.0.1.", "127.000.000.001", "10.0.0.1", "192.168.1.1", "169.254.169.254",
        "::", "0:0:0:0:0:ffff:127.0.0.1", "::ffff:0:127.0.0.1", "127.0.0.1%lo", "fe80::1",
    ]
    var h = bases[r.below(len(bases))]
    var junk = ["\0", "\r", "\n", " ", "/", "@", ":", "[", "]", "%", "\\", ".", "\t", "0", "9"]
    var k = r.below(4)
    if k == 0:
        return h
    for _ in range(k):
        var j = junk[r.below(len(junk))]
        var cut = r.below(h.byte_length() + 1)
        var at_end = r.below(2) == 0
        var head = String(unsafe_from_utf8=h.as_bytes()[:cut])
        var tail = String(unsafe_from_utf8=h.as_bytes()[cut:])
        h = (head + j + tail) if not at_end else (h + j)
    return h^


def _connect_fuzz(mut r: Rng, mut stats: List[Int]) raises:
    """connect() with hostile arguments: must raise tcp: errors, and never
    reach a loopback address when reject_private_ips is set."""
    var host = _host(r)
    var reject = r.below(2) == 0
    var port = PEER if r.below(4) != 0 else _pick(r, [0, 1, 65535, 65536, -1, 70000, 19502])
    if r.below(3) == 0:
        # reach connect() and fail there (refused, or no answer): the paths where a
        # descriptor is easiest to leak
        reject = False
        if r.below(2) == 0:
            host = "127.0.0.1"
            port = _pick(r, [1, 19502, 19503])
        else:
            host = "10.255.255.1"
            port = 80
    var s = TcpSocket()
    try:
        s.connect(host, port, reject, timeout_secs=_pick(r, [0, 1, 2, 30, -1, 10**9, 10**18]), timeout_ms=_ms(r))
        stats[0] += 1
        if reject and port == PEER:
            raise Error("VIOLATION: reject_private_ips=True connected to loopback via host '" + host + "'")
    except e:
        _tcp_error(e, "connect")
        stats[1] += 1


def _io_fuzz(mut r: Rng, mut stats: List[Int], first_fd: Int32, trace: Bool) raises -> Int32:
    var s = TcpSocket()
    s.connect("127.0.0.1", PEER, timeout_ms=_pick(r, [50, 100, 200, 1000]))
    if first_fd >= 0 and s.fd > first_fd + 2:
        raise Error("VIOLATION: descriptor leak: got fd " + String(s.fd) + ", baseline " + String(first_fd))
    var fd0 = s.fd
    var nops = 1 + r.below(5)
    for _ in range(nops):
        var op = r.below(11)
        var what = String("op ") + String(op)
        if trace:
            print("  op", op)
        try:
            if op == 0:
                var mx = _pick(r, [1, 2, 100, 4096, 65536, 1 << 20, (1 << 20) + 1, 1 << 30, 1 << 40])
                var got = s.recv_bytes(mx)
                if len(got) > min(mx, 1 << 20):
                    raise Error("VIOLATION: recv_bytes(" + String(mx) + ") returned " + String(len(got)))
            elif op == 1:
                var n = _pick(r, [0, 1, 5, 100, 5000, 100000, 1 << 40])
                var got = s.recv_bytes_exact(n)
                if len(got) != n:
                    raise Error("VIOLATION: recv_bytes_exact(" + String(n) + ") returned " + String(len(got)))
            elif op == 2:
                var mx = _pick(r, [0, 1, 1000, 100000, 1 << 20, 1 << 40])
                var got = s.recv_all(mx)
                if len(got) > mx + (1 << 20) + 65536:
                    raise Error("VIOLATION: recv_all(" + String(mx) + ") returned " + String(len(got)))
            elif op == 3:
                var n = _pick(r, [0, 1, 100, 4096, 70000, 1 << 20])
                _ = s.send_bytes(List[UInt8](length=n, fill=0x41))
            elif op == 4:
                _ = s.send(String("ping"))
            elif op == 5:
                _ = s.peer_closed()
            elif op == 6:
                var ms = _ms(r)
                if trace:
                    print("    set_timeout_ms", ms)
                s.set_timeout_ms(ms)
                _check_timeouts(s, ms, "set_timeout_ms")
                _short_again(s)
            elif op == 7:
                var secs = _pick(r, [0, 1, 2, 30, -1, 10**6, 10**18])
                s.set_timeout(secs)
                if secs >= 0 and secs <= 1_000_000:
                    _check_timeouts(s, secs * 1000, "set_timeout")
                _short_again(s)
            elif op == 8:
                s.set_nonblocking(r.below(2) == 0)
            elif op == 9:
                var fds = List[Int32]()
                var ev = List[Int16]()
                for _ in range(1 + r.below(4)):
                    fds.append(s.fd if r.below(3) != 0 else _pick_fd(r))
                    ev.append(Int16(r.below(64)) & (POLLIN | POLLOUT) if r.below(4) != 0 else Int16(r.below(64)))
                var out = poll_fds(fds, ev, r.below(60))
                if len(out) != len(fds):
                    raise Error("VIOLATION: poll_fds returned " + String(len(out)) + " results for " + String(len(fds)) + " fds")
            else:
                set_socket_timeout_ms(s.fd, _ms(r))
                _short_again(s)
        except e:
            var m = String(e)
            if m.startswith("VIOLATION"):
                raise e^
            _tcp_error(e, what)
            stats[2] += 1
    s.close()
    return fd0


def _pick_fd(mut r: Rng) -> Int32:
    return Int32(_pick(r, [-1, -2, 0x7FFFFFFF, 1000, 5000]))


def main() raises:
    var args = argv()
    var iters = 300
    var seed = UInt64(1)
    var trace = False
    if len(args) > 1:
        iters = Int(args[1])
    if len(args) > 2:
        seed = UInt64(Int(args[2]))
    if len(args) > 3 and args[3] == "trace":
        trace = True
    var r = Rng(seed)
    var stats = List[Int]()
    stats.append(0)  # fuzzed connects that succeeded
    stats.append(0)  # ... that raised a tcp: error
    stats.append(0)  # operations that raised a tcp: error
    var first_fd = Int32(-1)
    # warm-up: resolver descriptors open on first use and stay open
    for host in ["localhost", "10.255.255.1", "127.0.0.1"]:
        var w = TcpSocket()
        try:
            w.connect(host, PEER, timeout_ms=20)
        except e:
            pass
    for _ in range(iters):
        if r.below(3) == 0:
            _connect_fuzz(r, stats)
        else:
            var fd = _io_fuzz(r, stats, first_fd, trace)
            if first_fd < 0:
                first_fd = fd
    print("DONE iters=", iters, " connect ok/err=", stats[0], "/", stats[1], " op errors=", stats[2], sep="")
