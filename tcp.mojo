# ============================================================================
# tcp.mojo — TCP Socket Layer via C FFI
# ============================================================================
#
# Provides a TcpSocket struct wrapping POSIX socket syscalls:
#   socket(), connect(), send(), recv(), close()
#   DNS resolution via getaddrinfo() / freeaddrinfo()
#
# All system calls are made via Mojo's external_call FFI mechanism.
# Follows the same patterns as temperature_stats_mmap_v2.mojo (mmap FFI).
#
# ============================================================================

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc, UnsafePointer


# ============================================================================
# POSIX Constants
# ============================================================================

comptime AF_INET = 2
comptime SOCK_STREAM = 1
comptime IPPROTO_TCP = 6
comptime SHUT_RDWR = 2
comptime SOL_SOCKET = 1
comptime SO_RCVTIMEO = 20
comptime SO_SNDTIMEO = 21

# For getaddrinfo hints
comptime AI_PASSIVE = 1

# Default socket timeout (seconds)
comptime DEFAULT_TIMEOUT_SECS = 30


# ============================================================================
# C-compatible struct: sockaddr_in
# ============================================================================
#
# struct sockaddr_in {
#     sa_family_t    sin_family;   /* uint16_t */
#     in_port_t      sin_port;     /* uint16_t, network byte order */
#     struct in_addr sin_addr;     /* uint32_t */
#     char           sin_zero[8];  /* padding */
# };
#
# Total size: 16 bytes


@fieldwise_init
struct SockAddrIn(TrivialRegisterPassable):
    var sin_family: UInt16
    var sin_port: UInt16
    var sin_addr: UInt32
    var sin_zero: UInt64  # 8 bytes of padding


# ============================================================================
# FFI Wrapper Functions
# ============================================================================


def _socket() -> Int32:
    """Create a TCP socket. Returns file descriptor or -1 on error."""
    return external_call["socket", Int32](
        Int32(AF_INET), Int32(SOCK_STREAM), Int32(IPPROTO_TCP)
    )


def _connect(
    fd: Int32, addr_ptr: UnsafePointer[SockAddrIn, _], addrlen: UInt32
) -> Int32:
    """Connect socket to address. Returns 0 on success, -1 on error."""
    return external_call["connect", Int32](fd, Int(addr_ptr), Int32(addrlen))


def _send(fd: Int32, buf_addr: Int, length: Int, flags: Int32) -> Int:
    """Send data on socket. Returns bytes sent or -1 on error."""
    return external_call["send", Int](fd, buf_addr, length, flags)


def _recv(fd: Int32, buf_addr: Int, length: Int, flags: Int32) -> Int:
    """Receive data from socket. Returns bytes received, 0 on close, -1 on error."""
    return external_call["recv", Int](fd, buf_addr, length, flags)


def _close(fd: Int32) -> Int32:
    """Close a file descriptor."""
    return external_call["close", Int32](fd)


def _htons(port: UInt16) -> UInt16:
    """Convert 16-bit host byte order to network byte order."""
    return external_call["htons", UInt16](port)


def _shutdown(fd: Int32, how: Int32) -> Int32:
    """Shutdown socket for reading, writing, or both."""
    return external_call["shutdown", Int32](fd, how)


def _set_socket_timeouts(fd: Int32, timeout_secs: Int):
    """Set SO_RCVTIMEO and SO_SNDTIMEO on a socket.

    Uses struct timeval {time_t tv_sec; suseconds_t tv_usec;} — 16 bytes on
    Linux x86_64 (8 bytes each field).
    """
    # Allocate struct timeval (16 bytes: tv_sec=8, tv_usec=8)
    var tv = alloc[UInt8](16)
    # Zero out
    for i in range(16):
        (tv + i)[] = 0
    # Write tv_sec as 64-bit little-endian int at offset 0
    var sec_ptr = tv.bitcast[Int]()
    sec_ptr[] = timeout_secs
    # Set recv timeout
    _ = external_call["setsockopt", Int32](
        fd,
        Int32(SOL_SOCKET),
        Int32(SO_RCVTIMEO),
        Int(tv),
        Int32(16),
    )
    # Set send timeout
    _ = external_call["setsockopt", Int32](
        fd,
        Int32(SOL_SOCKET),
        Int32(SO_SNDTIMEO),
        Int(tv),
        Int32(16),
    )
    tv.free()


# ============================================================================
# DNS Resolution via getaddrinfo
# ============================================================================
#
# getaddrinfo returns a linked list of addrinfo structs.
# We extract the sockaddr_in from the first result.
#
# struct addrinfo {
#     int              ai_flags;      /* offset 0, 4 bytes */
#     int              ai_family;     /* offset 4, 4 bytes */
#     int              ai_socktype;   /* offset 8, 4 bytes */
#     int              ai_protocol;   /* offset 12, 4 bytes */
#     socklen_t        ai_addrlen;    /* offset 16, 4 bytes */
#     struct sockaddr *ai_addr;       /* offset 24, 8 bytes (with padding) */
#     char            *ai_canonname;  /* offset 32, 8 bytes */
#     struct addrinfo *ai_next;       /* offset 40, 8 bytes */
# };
# Total: 48 bytes on 64-bit Linux


def _resolve_host(host: String, port: Int) raises -> SockAddrIn:
    """Resolve hostname to sockaddr_in using getaddrinfo.

    Args:
        host: Hostname or IP address to resolve
        port: Port number

    Returns:
        SockAddrIn ready for connect()

    Raises:
        Error if DNS resolution fails
    """
    # Prepare C strings — keep originals alive while pointers are used
    var host_copy = host
    var host_ptr = host_copy.as_c_string_slice().unsafe_ptr()

    var port_str = String(port)
    var port_ptr = port_str.as_c_string_slice().unsafe_ptr()

    # Allocate pointer-to-pointer for result (getaddrinfo writes a pointer here)
    var result_ptr = alloc[Int](1)  # Will hold pointer to addrinfo linked list
    result_ptr[] = 0

    # Set up hints: we want AF_INET + SOCK_STREAM
    # addrinfo struct is 48 bytes on 64-bit Linux
    # We'll write the fields we care about at the correct offsets
    var hints_buf = alloc[UInt8](48)
    # Zero out
    for i in range(48):
        (hints_buf + i)[] = 0

    # ai_family at offset 4 (Int32 = AF_INET = 2)
    var hints_family_ptr = hints_buf.bitcast[Int32]()
    (hints_family_ptr + 1)[] = Int32(AF_INET)  # offset 4 bytes = 1 Int32
    # ai_socktype at offset 8
    (hints_family_ptr + 2)[] = Int32(SOCK_STREAM)  # offset 8 bytes = 2 Int32s

    # Call getaddrinfo
    var ret = external_call["getaddrinfo", Int32](
        Int(host_ptr),  # node (hostname)
        Int(port_ptr),  # service (port string)
        Int(hints_buf),  # hints
        Int(result_ptr),  # result (pointer-to-pointer)
    )

    hints_buf.free()

    if ret != 0:
        result_ptr.free()
        raise Error(
            "getaddrinfo failed for host: "
            + host
            + " (error "
            + String(Int(ret))
            + ")"
        )

    var addrinfo_ptr = result_ptr[]  # The actual addrinfo*
    result_ptr.free()

    if addrinfo_ptr == 0:
        raise Error("getaddrinfo returned no results for: " + host)

    # Extract ai_addr (pointer to sockaddr) from addrinfo struct.
    # ai_addr is at offset 24 in the addrinfo struct (on 64-bit Linux).
    # addrinfo_ptr is an Int (memory address). Read 8-byte pointer at offset 24.
    var addr_ptr_buf = alloc[Int](1)
    _ = external_call["memcpy", Int](Int(addr_ptr_buf), addrinfo_ptr + 24, 8)
    var sockaddr_addr = addr_ptr_buf[]  # This is the sockaddr* pointer
    addr_ptr_buf.free()

    if sockaddr_addr == 0:
        external_call["freeaddrinfo", NoneType](addrinfo_ptr)
        raise Error("getaddrinfo returned null sockaddr for: " + host)

    # Copy sockaddr_in from the address
    var addr = alloc[SockAddrIn](1)
    _ = external_call["memcpy", Int](Int(addr), sockaddr_addr, 16)
    var result = addr[]
    addr.free()

    # Free the addrinfo linked list
    external_call["freeaddrinfo", NoneType](addrinfo_ptr)

    return result


def _is_private_ip(sin_addr: UInt32) -> Bool:
    """Check if an IPv4 address (in network byte order) is private/reserved.

    Blocks:
        127.0.0.0/8   — loopback
        10.0.0.0/8    — private
        172.16.0.0/12 — private
        192.168.0.0/16 — private
        169.254.0.0/16 — link-local (includes AWS metadata 169.254.169.254)
        0.0.0.0/8     — "this network"
    """
    # sin_addr is in network byte order (big-endian).
    # On little-endian x86_64, byte 0 of the UInt32 is the first octet.
    # Extract octets via shifting the raw UInt32 value.
    # Network byte order: first octet is in the lowest memory address.
    # UInt32 on LE: byte[0] is bits 0-7, byte[1] is bits 8-15, etc.
    var b0 = Int(sin_addr & 0xFF)  # first octet
    var b1 = Int((sin_addr >> 8) & 0xFF)  # second octet

    # 127.0.0.0/8 — loopback
    if b0 == 127:
        return True
    # 10.0.0.0/8 — private
    if b0 == 10:
        return True
    # 172.16.0.0/12 — private
    if b0 == 172 and b1 >= 16 and b1 <= 31:
        return True
    # 192.168.0.0/16 — private
    if b0 == 192 and b1 == 168:
        return True
    # 169.254.0.0/16 — link-local
    if b0 == 169 and b1 == 254:
        return True
    # 0.0.0.0/8 — "this network"
    if b0 == 0:
        return True
    return False


# ============================================================================
# TcpSocket — High-level TCP Socket Wrapper
# ============================================================================


struct TcpSocket(Movable):
    """TCP socket wrapper with connect, send, recv, close operations."""

    var fd: Int32
    var connected: Bool

    def __init__(out self):
        self.fd = -1
        self.connected = False

    def __moveinit__(out self, deinit take: Self):
        self.fd = take.fd
        self.connected = take.connected

    def connect(
        mut self,
        host: String,
        port: Int,
        reject_private_ips: Bool = False,
    ) raises:
        """Connect to a remote host:port via TCP.

        Steps:
            1. Resolve hostname to IP via getaddrinfo
            2. (Optional) Check resolved IP against private ranges
            3. Create socket
            4. Connect to resolved address

        Args:
            host: Hostname or IP address
            port: Port number
            reject_private_ips: If True, raise on private/reserved IPs (SSRF protection)
        """
        # Step 1: DNS resolution
        var addr = _resolve_host(host, port)

        # Step 2: SSRF protection — reject private/reserved IPs
        if reject_private_ips and _is_private_ip(addr.sin_addr):
            raise Error(
                "connection to private/reserved IP address blocked (SSRF protection)"
            )

        # Step 2: Create socket
        self.fd = _socket()
        if self.fd < 0:
            raise Error("failed to create socket")

        # Step 2.5: Set socket timeouts (recv/send)
        _set_socket_timeouts(self.fd, DEFAULT_TIMEOUT_SECS)

        # Step 3: Connect
        var addr_ptr = alloc[SockAddrIn](1)
        addr_ptr[] = addr
        var ret = _connect(self.fd, addr_ptr, 16)
        addr_ptr.free()

        if ret < 0:
            _ = _close(self.fd)
            self.fd = -1
            raise Error("failed to connect to " + host + ":" + String(port))

        self.connected = True

    def send(self, data: String) raises -> Int:
        """Send a string over the socket.

        Args:
            data: The string data to send

        Returns:
            Number of bytes actually sent

        Raises:
            Error if socket is not connected or send fails
        """
        if not self.connected:
            raise Error("socket not connected")

        var data_copy = data
        var ptr = data_copy.as_c_string_slice().unsafe_ptr()
        var sent = _send(self.fd, Int(ptr), len(data), Int32(0))

        if sent < 0:
            raise Error("send failed")
        return sent

    def recv(self, max_bytes: Int = 4096) raises -> String:
        """Receive data from socket as a string.

        Args:
            max_bytes: Maximum number of bytes to receive

        Returns:
            Received data as String (may be empty if connection closed)

        Raises:
            Error if socket is not connected or recv fails
        """
        if not self.connected:
            raise Error("socket not connected")

        var buf = alloc[UInt8](max_bytes)
        var received = _recv(self.fd, Int(buf), max_bytes, Int32(0))

        if received < 0:
            buf.free()
            raise Error("recv failed")

        if received == 0:
            buf.free()
            return String("")

        # Build string from received bytes
        var bytes = List[UInt8](capacity=Int(received))
        for i in range(Int(received)):
            bytes.append((buf + i)[])
        buf.free()

        return String(unsafe_from_utf8=bytes^)

    def recv_bytes(self, max_bytes: Int = 4096) raises -> List[UInt8]:
        """Receive up to max_bytes from socket, returning raw bytes.

        Unlike recv() which returns String, this returns List[UInt8] for
        binary-safe use (keep-alive connections, chunked bodies).

        Returns:
            Received bytes (may be empty if connection closed)
        """
        if not self.connected:
            raise Error("socket not connected")

        var buf = alloc[UInt8](max_bytes)
        var received = _recv(self.fd, Int(buf), max_bytes, Int32(0))

        if received < 0:
            buf.free()
            raise Error("tcp: recv_bytes failed")

        var result = List[UInt8](capacity=Int(received))
        for i in range(Int(received)):
            result.append((buf + i)[])
        buf.free()
        return result^

    def recv_bytes_exact(self, n: Int) raises -> List[UInt8]:
        """Read exactly n bytes, looping until done or connection closes.

        Raises:
            Error if connection closes before n bytes are received.
        """
        var result = List[UInt8](capacity=n)
        while len(result) < n:
            var chunk = self.recv_bytes(n - len(result))
            if len(chunk) == 0:
                raise Error(
                    "tcp: connection closed after "
                    + String(len(result))
                    + " of "
                    + String(n)
                    + " bytes"
                )
            for i in range(len(chunk)):
                result.append(chunk[i])
        return result^

    def recv_all(self, max_size: Int = 104857600) raises -> List[UInt8]:
        """Receive all data until the connection is closed.

        Reads in a loop until recv returns 0 (connection closed by peer).
        Used with HTTP/1.1 Connection: close to read the full response.
        Uses a 64KB growing buffer to minimize syscalls and copies.

        Args:
            max_size: Maximum response size in bytes (default 100 MB).

        Returns:
            All received data as a byte list
        """
        if not self.connected:
            raise Error("socket not connected")

        var CHUNK_SIZE = 65536
        var capacity = CHUNK_SIZE
        var buf = alloc[UInt8](capacity)
        var total = 0

        while True:
            if total + CHUNK_SIZE > capacity:
                var new_cap = capacity * 2
                var new_buf = alloc[UInt8](new_cap)
                _ = external_call["memcpy", Int](Int(new_buf), Int(buf), total)
                buf.free()
                buf = new_buf
                capacity = new_cap
            var received = _recv(
                self.fd, Int(buf + total), CHUNK_SIZE, Int32(0)
            )
            if received < 0:
                buf.free()
                raise Error("recv failed during recv_all")
            if received == 0:
                break
            total += Int(received)
            if total > max_size:
                buf.free()
                raise Error(
                    "response exceeds maximum size of "
                    + String(max_size)
                    + " bytes"
                )

        var result = List[UInt8](capacity=total)
        for i in range(total):
            result.append((buf + i)[])
        buf.free()
        return result^

    def close(mut self):
        """Close the socket and release resources."""
        if self.fd >= 0:
            _ = _shutdown(self.fd, Int32(SHUT_RDWR))
            _ = _close(self.fd)
            self.fd = -1
            self.connected = False
