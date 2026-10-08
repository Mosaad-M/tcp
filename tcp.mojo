# ============================================================================
# tcp.mojo — TCP client sockets over POSIX (Linux and macOS)
# ============================================================================
#
# TcpSocket: connect (DNS, IPv4 and IPv6, every resolved address in turn,
# optional SSRF filtering, timeouts), complete sends, receives, close.
#
# Ownership: a TcpSocket closes its fd when it is destroyed. Mojo destroys a
# value right after its last use, so code that hands the fd to something
# else (e.g. TlsSocket) must take it with detach(): TlsSocket(tcp.detach()).
#
# FFI: a Mojo program may declare each C function with one signature only.
# tcp declares no C function that std declares (open/read/write, fcntl,
# strerror, errno access, getenv, clock_gettime): errno comes from
# std.ffi.get_errno. Socket calls use the signatures tls and the other
# packages share (tls/tests/test_ffi_compat.mojo).
#
# ============================================================================

from std.ffi import external_call, get_errno, ErrNo
from std.memory import alloc
from std.sys.info import CompilationTarget


# ============================================================================
# POSIX constants (Linux / macOS)
# ============================================================================

comptime _MACOS = CompilationTarget.is_macos()

comptime AF_UNSPEC: Int32 = 0
comptime AF_INET: Int32 = 2
comptime AF_INET6: Int32 = 30 if _MACOS else 10
comptime SOCK_STREAM: Int32 = 1
comptime IPPROTO_TCP: Int32 = 6
comptime SHUT_RDWR: Int32 = 2
comptime SOL_SOCKET: Int32 = 0xFFFF if _MACOS else 1
comptime SO_RCVTIMEO: Int32 = 0x1006 if _MACOS else 20
comptime SO_SNDTIMEO: Int32 = 0x1005 if _MACOS else 21
comptime SO_ERROR: Int32 = 0x1007 if _MACOS else 4
comptime SO_NOSIGPIPE: Int32 = 0x1022            # macOS only
comptime FIONBIO: UInt64 = 0x8004667E if _MACOS else 0x5421
comptime MSG_NOSIGNAL: Int32 = 0 if _MACOS else 0x4000
comptime POLLOUT: Int16 = 4

comptime EINTR: Int32 = 4
comptime EPIPE: Int32 = 32
comptime EAGAIN: Int32 = 35 if _MACOS else 11
comptime EINPROGRESS: Int32 = 36 if _MACOS else 115
comptime ECONNRESET: Int32 = 54 if _MACOS else 104
comptime ETIMEDOUT: Int32 = 60 if _MACOS else 110

# Default socket timeout (seconds)
comptime DEFAULT_TIMEOUT_SECS = 30

comptime _SSRF_MESSAGE = "connection to private/reserved IP address blocked (SSRF protection)"


# ============================================================================
# FFI wrappers
# ============================================================================


def _socket(family: Int32) -> Int32:
    return external_call["socket", Int32](family, SOCK_STREAM, IPPROTO_TCP)


def _connect(fd: Int32, addr: Int, addrlen: Int32) -> Int32:
    return external_call["connect", Int32](fd, addr, addrlen)


def _send(fd: Int32, buf_addr: Int, length: Int, flags: Int32) -> Int:
    """send(): the same argument types as tls and the other packages."""
    return external_call["send", Int](fd, buf_addr, length, flags)


def _recv(fd: Int32, buf_addr: Int, length: Int, flags: Int32) -> Int:
    return external_call["recv", Int](fd, buf_addr, length, flags)


def _close(fd: Int32) -> Int32:
    return external_call["close", Int32](fd)


def _shutdown(fd: Int32, how: Int32) -> Int32:
    return external_call["shutdown", Int32](fd, how)


def _setsockopt(fd: Int32, level: Int32, name: Int32, value: Int, length: Int32) -> Int32:
    return external_call["setsockopt", Int32](fd, level, name, value, length)


def _errno() -> Int32:
    return Int32(get_errno().value)


def _err_text(code: Int32) -> String:
    """strerror() text, through std (ErrNo cannot stringify 0 on macOS)."""
    if code == 0:
        return String("unknown error")
    return String(ErrNo(code))


def _peek(addr: Int, n: Int) -> List[UInt8]:
    """Copy n bytes from a C address."""
    var buf = alloc[UInt8](n)
    _ = external_call["memcpy", Int](Int(buf), addr, n)
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(buf[unsafe_offset=i])
    buf.unsafe_free()
    return out^


def _le32(b: List[UInt8], off: Int) -> Int:
    return Int(b[off]) | (Int(b[off + 1]) << 8) | (Int(b[off + 2]) << 16) | (Int(b[off + 3]) << 24)


def _le64(b: List[UInt8], off: Int) -> Int:
    var v = 0
    for i in range(8):
        v |= Int(b[off + i]) << (8 * i)
    return v


def _set_int_opt(fd: Int32, level: Int32, name: Int32, value: Int32) -> Int32:
    var p = alloc[Int32](1)
    p[unsafe_offset=0] = value
    var rc = _setsockopt(fd, level, name, Int(p), Int32(4))
    p.unsafe_free()
    return rc


def _set_nonblocking(fd: Int32, on: Bool) -> Int32:
    """ioctl(FIONBIO): fcntl is declared by std, ioctl is not. ioctl is
    variadic (on Apple arm64 the variadic argument goes on the stack)."""
    var v = alloc[Int32](1)
    v[unsafe_offset=0] = 1 if on else 0
    var rc = external_call["ioctl", Int32, num_fixed_args=2](fd, FIONBIO, Int(v))
    v.unsafe_free()
    return rc


def _set_socket_timeouts(fd: Int32, timeout_secs: Int) raises:
    """SO_RCVTIMEO / SO_SNDTIMEO for sends and receives (struct timeval,
    16 bytes on both platforms; 0 = no timeout)."""
    var tv = alloc[UInt8](16)
    for i in range(16):
        tv[unsafe_offset=i] = 0
    tv.unsafe_bitcast[Int]()[unsafe_offset=0] = timeout_secs
    var rc1 = _setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, Int(tv), Int32(16))
    var rc2 = _setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, Int(tv), Int32(16))
    tv.unsafe_free()
    if rc1 != 0 or rc2 != 0:
        raise Error("tcp: setting socket timeouts failed: " + _err_text(_errno()))


def _wait_connected(fd: Int32, timeout_secs: Int) -> Int32:
    """Wait for a non-blocking connect() to finish. Returns 0 or the connect
    error (ETIMEDOUT when the timeout passes first)."""
    var pfd = alloc[UInt8](8)  # struct pollfd { int fd; short events; short revents; }
    for i in range(8):
        pfd[unsafe_offset=i] = 0
    pfd.unsafe_bitcast[Int32]()[unsafe_offset=0] = fd
    pfd.unsafe_bitcast[Int16]()[unsafe_offset=2] = POLLOUT
    var ms = Int32(timeout_secs * 1000) if timeout_secs > 0 else Int32(-1)
    var rc: Int32
    while True:
        rc = external_call["poll", Int32](Int(pfd), Int(1), ms)
        if rc >= 0 or _errno() != EINTR:
            break
    pfd.unsafe_free()
    if rc == 0:
        return ETIMEDOUT
    if rc < 0:
        return _errno()
    var val = alloc[Int32](2)  # value, then socklen_t length
    val[unsafe_offset=0] = 0
    val[unsafe_offset=1] = 4
    var g = external_call["getsockopt", Int32](
        fd, SOL_SOCKET, SO_ERROR, Int(val), Int(val.unsafe_offset(1))
    )
    var err = val[unsafe_offset=0] if g == 0 else _errno()
    val.unsafe_free()
    return err


# ============================================================================
# Addresses
# ============================================================================


struct _Addr(Copyable, Movable):
    """A resolved socket address: the raw sockaddr_in / sockaddr_in6 bytes."""
    var family: Int32
    var sa: List[UInt8]

    def __init__(out self, family: Int32, var sa: List[UInt8]):
        self.family = family
        self.sa = sa^

    def ip_bytes(self) -> List[UInt8]:
        """4 bytes (IPv4) or 16 bytes (IPv6), network order."""
        var out = List[UInt8]()
        if self.family == AF_INET:
            for i in range(4, 8):
                out.append(self.sa[i])
        else:
            for i in range(8, 24):
                out.append(self.sa[i])
        return out^


def _sa_header(length: Int, family: Int32) -> List[UInt8]:
    """sin_len + sin_family (macOS: 1 byte each) or sa_family (Linux: 2 bytes)."""
    var out = List[UInt8]()
    comptime if _MACOS:
        out.append(UInt8(length))
        out.append(UInt8(family))
    else:
        out.append(UInt8(family & 0xFF))
        out.append(UInt8((family >> 8) & 0xFF))
    return out^


def _addr_v4(a: Int, b: Int, c: Int, d: Int, port: Int) -> _Addr:
    var sa = _sa_header(16, AF_INET)
    sa.append(UInt8((port >> 8) & 0xFF))
    sa.append(UInt8(port & 0xFF))
    sa.append(UInt8(a))
    sa.append(UInt8(b))
    sa.append(UInt8(c))
    sa.append(UInt8(d))
    for _ in range(8):
        sa.append(0)
    return _Addr(AF_INET, sa^)


def _addr_v6(ip: List[UInt8], port: Int) -> _Addr:
    var sa = _sa_header(28, AF_INET6)
    sa.append(UInt8((port >> 8) & 0xFF))
    sa.append(UInt8(port & 0xFF))
    for _ in range(4):
        sa.append(0)  # sin6_flowinfo
    for i in range(16):
        sa.append(ip[i])
    for _ in range(4):
        sa.append(0)  # sin6_scope_id
    return _Addr(AF_INET6, sa^)


def _hex(v: Int) -> String:
    comptime DIGITS = "0123456789abcdef"
    if v == 0:
        return String("0")
    var out = String("")
    var x = v
    var d = String(DIGITS).as_bytes()
    var tmp = List[UInt8]()
    while x > 0:
        tmp.append(d[x & 0xF])
        x >>= 4
    for i in range(len(tmp) - 1, -1, -1):
        out += chr(Int(tmp[i]))
    return out


def _format_addr(a: _Addr) -> String:
    """93.184.216.34 or [2606:2800:0:0:0:0:0:1] (groups, no :: compression)."""
    var ip = a.ip_bytes()
    if a.family == AF_INET:
        return String(ip[0]) + "." + String(ip[1]) + "." + String(ip[2]) + "." + String(ip[3])
    var out = String("[")
    for g in range(8):
        if g > 0:
            out += ":"
        out += _hex((Int(ip[2 * g]) << 8) | Int(ip[2 * g + 1]))
    return out + "]"


# ============================================================================
# SSRF filter: special-purpose and non-global addresses
# ============================================================================


def _is_private_v4_octets(b0: Int, b1: Int, b2: Int) -> Bool:
    """RFC 6890 special-purpose IPv4 ranges (plus multicast and 240/4)."""
    if b0 == 0 or b0 == 10 or b0 == 127:
        return True                                  # this network, private, loopback
    if b0 == 100 and b1 >= 64 and b1 <= 127:
        return True                                  # 100.64/10 shared (CGNAT)
    if b0 == 169 and b1 == 254:
        return True                                  # link-local (cloud metadata)
    if b0 == 172 and b1 >= 16 and b1 <= 31:
        return True                                  # private
    if b0 == 192 and b1 == 0 and (b2 == 0 or b2 == 2):
        return True                                  # IETF assignments, TEST-NET-1
    if b0 == 192 and b1 == 88 and b2 == 99:
        return True                                  # 6to4 relay anycast
    if b0 == 192 and b1 == 168:
        return True                                  # private
    if b0 == 198 and (b1 == 18 or b1 == 19):
        return True                                  # benchmarking
    if b0 == 198 and b1 == 51 and b2 == 100:
        return True                                  # TEST-NET-2
    if b0 == 203 and b1 == 0 and b2 == 113:
        return True                                  # TEST-NET-3
    if b0 >= 224:
        return True                                  # multicast, reserved, broadcast
    return False


def _is_private_ip(sin_addr: UInt32) -> Bool:
    """IPv4 address as stored in sin_addr (network order read little-endian:
    the first octet is the low byte)."""
    return _is_private_v4_octets(
        Int(sin_addr & 0xFF), Int((sin_addr >> 8) & 0xFF), Int((sin_addr >> 16) & 0xFF)
    )


def _is_private_ip6(b: List[UInt8]) -> Bool:
    """IPv6 (16 bytes, network order). Addresses that embed an IPv4 address
    (IPv4-compatible/-mapped, NAT64 64:ff9b::/96, 6to4 2002::/16) are judged
    by that address."""
    var first12_zero = True
    for i in range(12):
        if b[i] != 0:
            first12_zero = False
    if first12_zero:
        return _is_private_v4_octets(Int(b[12]), Int(b[13]), Int(b[14]))  # ::, ::1, ::a.b.c.d
    var mapped = b[10] == 0xFF and b[11] == 0xFF
    for i in range(10):
        if b[i] != 0:
            mapped = False
    if mapped:
        return _is_private_v4_octets(Int(b[12]), Int(b[13]), Int(b[14]))  # ::ffff:a.b.c.d
    if b[0] == 0x00 and b[1] == 0x64 and b[2] == 0xFF and b[3] == 0x9B:
        var nat64 = True
        for i in range(4, 12):
            if b[i] != 0:
                nat64 = False
        if nat64:
            return _is_private_v4_octets(Int(b[12]), Int(b[13]), Int(b[14]))
        if b[4] == 0x00 and b[5] == 0x01:
            return True                              # 64:ff9b:1::/48 local-use NAT64
    if b[0] == 0x20 and b[1] == 0x02:
        return _is_private_v4_octets(Int(b[2]), Int(b[3]), Int(b[4]))  # 6to4
    if (b[0] & 0xFE) == 0xFC:
        return True                                  # fc00::/7 unique local
    if b[0] == 0xFE and (b[1] & 0xC0) >= 0x80:
        return True                                  # fe80::/10 link-local, fec0::/10 site-local
    if b[0] == 0xFF:
        return True                                  # multicast
    if b[0] == 0x01 and b[1] == 0x00:
        var discard = True
        for i in range(2, 8):
            if b[i] != 0:
                discard = False
        if discard:
            return True                              # 100::/64 discard-only
    if b[0] == 0x20 and b[1] == 0x01:
        if (b[2] & 0xFE) == 0:
            return True                              # 2001::/23 IETF (incl. Teredo)
        if b[2] == 0x0D and b[3] == 0xB8:
            return True                              # 2001:db8::/32 documentation
    return False


def _is_private_addr(a: _Addr) -> Bool:
    var ip = a.ip_bytes()
    if a.family == AF_INET:
        return _is_private_v4_octets(Int(ip[0]), Int(ip[1]), Int(ip[2]))
    return _is_private_ip6(ip)


# ============================================================================
# DNS resolution via getaddrinfo
# ============================================================================
#
# struct addrinfo (64-bit):  flags@0 family@4 socktype@8 protocol@12
# addrlen@16; Linux: ai_addr@24 ai_canonname@32; macOS: ai_canonname@24
# ai_addr@32; ai_next@40 on both.

comptime _AI_ADDR_OFFSET = 32 if _MACOS else 24


def _gai_error(code: Int32) -> String:
    var p = external_call["gai_strerror", Int](code)
    if p == 0:
        return "error " + String(Int(code))
    var n = external_call["strlen", Int](p)
    var text = _peek(p, n)
    return String(unsafe_from_utf8=text^)


def _resolve_all(host: String, port: Int) raises -> List[_Addr]:
    """Every TCP address of host:port, IPv4 first, then IPv6 (resolver
    order within each family). IPv4 first keeps dual-stack hosts fast on
    networks with broken IPv6."""
    if host.byte_length() == 0:
        raise Error("tcp: empty host name")
    for b in host.as_bytes():
        if b == 0:
            raise Error("tcp: host name contains a NUL byte")
    var host_copy = host
    var port_str = String(port)
    var result_ptr = alloc[Int](1)
    result_ptr[unsafe_offset=0] = 0
    var hints = alloc[UInt8](48)
    for i in range(48):
        hints[unsafe_offset=i] = 0
    hints.unsafe_bitcast[Int32]()[unsafe_offset=1] = AF_UNSPEC
    hints.unsafe_bitcast[Int32]()[unsafe_offset=2] = SOCK_STREAM
    var ret = external_call["getaddrinfo", Int32](
        Int(host_copy.as_c_string_slice().unsafe_ptr()),
        Int(port_str.as_c_string_slice().unsafe_ptr()),
        Int(hints),
        Int(result_ptr),
    )
    hints.unsafe_free()
    var head = result_ptr[unsafe_offset=0]
    result_ptr.unsafe_free()
    if ret != 0:
        raise Error("tcp: cannot resolve " + host + ": " + _gai_error(ret))

    var v4 = List[_Addr]()
    var v6 = List[_Addr]()
    var node = head
    while node != 0:
        var ai = _peek(node, 48)
        var family = Int32(_le32(ai, 4))
        var addrlen = _le32(ai, 16)
        var sa_ptr = _le64(ai, _AI_ADDR_OFFSET)
        if sa_ptr != 0:
            if family == AF_INET and addrlen >= 16:
                v4.append(_Addr(AF_INET, _peek(sa_ptr, 16)))
            elif family == AF_INET6 and addrlen >= 28:
                v6.append(_Addr(AF_INET6, _peek(sa_ptr, 28)))
        node = _le64(ai, 40)
    if head != 0:
        external_call["freeaddrinfo", NoneType](head)

    for i in range(len(v6)):
        v4.append(v6[i].copy())
    if len(v4) == 0:
        raise Error("tcp: cannot resolve " + host + ": no IPv4 or IPv6 address")
    return v4^


# ============================================================================
# TcpSocket
# ============================================================================


struct TcpSocket(Movable):
    """A TCP client socket. Closes its fd when destroyed; use detach() to hand
    the fd to another owner (e.g. TlsSocket(tcp.detach()))."""

    var fd: Int32
    var connected: Bool

    def __init__(out self):
        self.fd = -1
        self.connected = False

    def __init__(out self, *, deinit move: Self):
        self.fd = move.fd
        self.connected = move.connected

    def __deinit__(deinit self):
        if self.fd >= 0:
            _ = _close(self.fd)

    def connect(
        mut self,
        host: String,
        port: Int,
        reject_private_ips: Bool = False,
        timeout_secs: Int = DEFAULT_TIMEOUT_SECS,
    ) raises:
        """Connect to host:port, trying every resolved address (IPv4 first).

        Args:
            host: Host name or IP literal (IPv4 or IPv6, without brackets).
            port: 1-65535.
            reject_private_ips: Skip private and special-purpose addresses
                (SSRF protection); raises if no address is left.
            timeout_secs: Connect, send and receive timeout per address
                (0 = none). With several addresses the total can be longer.

        A socket that is already open is closed first.
        """
        if port < 1 or port > 65535:
            raise Error("tcp: invalid port " + String(port) + " (must be 1-65535)")
        if timeout_secs < 0:
            raise Error("tcp: timeout_secs must be >= 0")
        self.close()
        var addrs = _resolve_all(host, port)
        self._connect_addrs(addrs, host, port, reject_private_ips, timeout_secs)

    def _connect_addrs(
        mut self,
        addrs: List[_Addr],
        host: String,
        port: Int,
        reject_private_ips: Bool,
        timeout_secs: Int,
    ) raises:
        """Try each address in order until one connects."""
        self.close()
        var failures = String("")
        var tried = 0
        for i in range(len(addrs)):
            ref a = addrs[i]
            if reject_private_ips and _is_private_addr(a):
                continue
            tried += 1
            var reason = self._try_connect(a, timeout_secs)
            if reason == "":
                self.connected = True
                return
            if failures.byte_length() > 0:
                failures += "; "
            failures += _format_addr(a) + ": " + reason
        if tried == 0:
            raise Error(_SSRF_MESSAGE + ": " + host + " has only private/reserved addresses")
        raise Error("tcp: cannot connect to " + host + ":" + String(port) + " (" + failures + ")")

    def _try_connect(mut self, a: _Addr, timeout_secs: Int) -> String:
        """Connect to one address; "" on success, else the reason (fd closed)."""
        var fd = _socket(a.family)
        if fd < 0:
            return "socket() failed: " + _err_text(_errno())
        comptime if _MACOS:
            _ = _set_int_opt(fd, SOL_SOCKET, SO_NOSIGPIPE, Int32(1))
        try:
            _set_socket_timeouts(fd, timeout_secs)
        except e:
            _ = _close(fd)
            return String(e)
        # Non-blocking connect + poll: the only connect timeout that works on
        # both platforms (macOS ignores SO_SNDTIMEO for connect)
        if _set_nonblocking(fd, True) != 0:
            var e = _errno()
            _ = _close(fd)
            return "ioctl(FIONBIO) failed: " + _err_text(e)
        var n = len(a.sa)
        var buf = alloc[UInt8](n)
        for i in range(n):
            buf[unsafe_offset=i] = a.sa[i]
        var rc = _connect(fd, Int(buf), Int32(n))
        buf.unsafe_free()
        var err = Int32(0) if rc == 0 else _errno()
        if err == EINPROGRESS or err == EINTR:
            err = _wait_connected(fd, timeout_secs)
        if err == 0 and _set_nonblocking(fd, False) != 0:
            err = _errno()
        if err == 0:
            self.fd = fd
            return ""
        _ = _close(fd)
        if err == ETIMEDOUT:
            return "timed out"
        return _err_text(err)

    def detach(mut self) -> Int32:
        """Give up ownership of the fd and return it (the caller closes it)."""
        var fd = self.fd
        self.fd = -1
        self.connected = False
        return fd

    # ── Sending ──────────────────────────────────────────────────────────────

    def _send_all(self, ptr: Int, n: Int) raises -> Int:
        if not self.connected:
            raise Error("tcp: socket not connected")
        var total = 0
        while total < n:
            var sent = _send(self.fd, ptr + total, n - total, MSG_NOSIGNAL)
            if sent < 0:
                var err = _errno()
                if err == EINTR:
                    continue
                if err == EAGAIN:
                    raise Error(
                        "tcp: send timed out (" + String(total) + " of " + String(n) + " bytes sent)"
                    )
                if err == EPIPE or err == ECONNRESET:
                    raise Error("tcp: connection closed by peer")
                raise Error("tcp: send failed: " + _err_text(err))
            total += sent
        return total

    def send(self, data: String) raises -> Int:
        """Send all of data. Returns its length in bytes; raises on timeout,
        on a closed peer ("tcp: connection closed by peer") or other errors."""
        var bytes = data.as_bytes()
        return self._send_all(Int(bytes.unsafe_ptr()), len(bytes))

    def send_bytes(self, data: List[UInt8]) raises -> Int:
        """Send all of data (binary). Same behavior as send()."""
        return self._send_all(Int(data.unsafe_ptr()), len(data))

    # ── Receiving ────────────────────────────────────────────────────────────

    def _recv_into(self, ptr: Int, max_bytes: Int) raises -> Int:
        """One recv(): bytes received, 0 at end of stream."""
        if not self.connected:
            raise Error("tcp: socket not connected")
        while True:
            var got = _recv(self.fd, ptr, max_bytes, Int32(0))
            if got >= 0:
                return got
            var err = _errno()
            if err == EINTR:
                continue
            if err == EAGAIN:
                raise Error("tcp: recv timed out")
            if err == ECONNRESET:
                raise Error("tcp: connection reset by peer")
            raise Error("tcp: recv failed: " + _err_text(err))

    def recv_bytes(self, max_bytes: Int = 4096) raises -> List[UInt8]:
        """Up to max_bytes (> 0); an empty result means end of stream."""
        if max_bytes <= 0:
            raise Error("tcp: recv_bytes: max_bytes must be > 0")
        var buf = alloc[UInt8](max_bytes)
        var got: Int
        try:
            got = self._recv_into(Int(buf), max_bytes)
        except e:
            buf.unsafe_free()
            raise e^
        var result = List[UInt8](capacity=got)
        for i in range(got):
            result.append(buf[unsafe_offset=i])
        buf.unsafe_free()
        return result^

    def recv(self, max_bytes: Int = 4096) raises -> String:
        """Like recv_bytes, as a String. The bytes are not checked to be UTF-8
        and a chunk can end inside a character: use recv_bytes for binary or
        streamed text."""
        return String(unsafe_from_utf8=self.recv_bytes(max_bytes))

    def recv_bytes_exact(self, n: Int) raises -> List[UInt8]:
        """Exactly n bytes; raises if the stream ends first."""
        var result = List[UInt8](capacity=n)
        while len(result) < n:
            var chunk = self.recv_bytes(n - len(result))
            if len(chunk) == 0:
                raise Error(
                    "tcp: connection closed after " + String(len(result)) + " of " + String(n) + " bytes"
                )
            for i in range(len(chunk)):
                result.append(chunk[i])
        return result^

    def recv_all(self, max_size: Int = 104857600) raises -> List[UInt8]:
        """Everything until the peer closes (at most max_size bytes, default
        100 MB)."""
        comptime CHUNK_SIZE = 65536
        var capacity = CHUNK_SIZE
        var buf = alloc[UInt8](capacity)
        var total = 0
        while True:
            if total + CHUNK_SIZE > capacity:
                var new_buf = alloc[UInt8](capacity * 2)
                _ = external_call["memcpy", Int](Int(new_buf), Int(buf), total)
                buf.unsafe_free()
                buf = new_buf
                capacity *= 2
            var got: Int
            try:
                got = self._recv_into(Int(buf.unsafe_offset(total)), CHUNK_SIZE)
            except e:
                buf.unsafe_free()
                raise e^
            if got == 0:
                break
            total += got
            if total > max_size:
                buf.unsafe_free()
                raise Error("tcp: response exceeds maximum size of " + String(max_size) + " bytes")
        var result = List[UInt8](capacity=total)
        for i in range(total):
            result.append(buf[unsafe_offset=i])
        buf.unsafe_free()
        return result^

    def close(mut self):
        """Shut down and close the socket. Safe to call more than once."""
        if self.fd >= 0:
            _ = _shutdown(self.fd, SHUT_RDWR)
            _ = _close(self.fd)
            self.fd = -1
        self.connected = False
