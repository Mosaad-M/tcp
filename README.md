# tcp

A TCP client socket for [Mojo](https://www.modular.com/mojo), written against POSIX
directly: no C helper, no dependencies.

## Install

With [mojo-pkg](https://github.com/Mosaad-M/mojo-pkg):

```toml
[dependencies]
tcp = { git = "Mosaad-M/tcp", version = ">=2.2.0" }
```

Or clone the repository and build with `-I path/to/tcp`. Requires Mojo >= 1.2.0 on
linux-64 or osx-arm64. Release history is in [CHANGELOG.md](CHANGELOG.md).

## Usage

```mojo
from tcp import TcpSocket

var sock = TcpSocket()
sock.connect("example.com", 80, timeout_secs=10)
_ = sock.send("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
var response = sock.recv_all()        # List[UInt8], until the server closes
sock.close()                          # optional: the socket closes when destroyed
```

## API

| | |
|---|---|
| `connect(host, port, reject_private_ips=False, timeout_secs=30, nodelay=True, timeout_ms=0)` | Resolves `host` (name, IPv4 or IPv6 literal) and tries each address, IPv4 first, until one connects. `timeout_secs` (0 = none) bounds the whole connect across all addresses, then applies to every send and receive. `timeout_ms` (> 0) replaces it, in milliseconds. DNS resolution is not covered: `getaddrinfo` uses the system resolver's own timeout. Ports must be 1-65535. Connecting an open socket closes it first. |
| `send(data: String) -> Int`, `send_bytes(data: List[UInt8]) -> Int` | Send all of `data` and return its length. |
| `recv_bytes(max_bytes=4096) -> List[UInt8]` | Up to `max_bytes` (> 0, at most 1 MiB per call). Empty means the peer closed. |
| `recv_bytes_exact(n)` | Exactly `n` bytes, or an error if the stream ends first. Memory grows with the bytes that arrive, so a large `n` from an untrusted peer reserves nothing up front (callers should still cap such lengths). |
| `recv_all(max_size=100 MB)` | Everything until the peer closes. Raises if more than `max_size` bytes arrive. |
| `recv(max_bytes) -> String` | Like `recv_bytes`, as a String that is not checked for UTF-8. Prefer `recv_bytes`. |
| `set_timeout_ms(ms)`, `set_timeout(secs)` | Change the send and receive timeout of a connected socket (0 = none). A wait that long raises `tcp: recv timed out` or `tcp: send timed out`. The kernel rounds to its clock tick, a few ms. `set_socket_timeout_ms(fd, ms)` does the same for a raw descriptor you own. |
| `set_nonblocking(on)` | In non-blocking mode `recv` and `send` raise `tcp: recv timed out` or `tcp: send timed out` at once instead of waiting. Wait with `poll_fds` first. `connect` leaves the socket blocking. |
| `poll_fds(fds, events, timeout_ms) -> List[Int16]` | `poll(2)` over several descriptors with `POLLIN` or `POLLOUT`. Returns each one's `revents` (`POLLERR`, `POLLHUP` and `POLLNVAL` can appear too; all zero means the time ran out). `timeout_ms` < 0 waits forever, 0 checks and returns. Keep each `TcpSocket` alive until it returns (see Ownership). |
| `peer_closed() -> Bool` | Whether the peer has closed or reset the connection, or the socket is not connected. Does not block or consume data. Check it before reusing a pooled connection. |
| `detach() -> Int32` | Gives up ownership of the file descriptor (see Ownership). |
| `close()` | Shuts down and closes. Safe to call twice. |
| `fd`, `connected` | The descriptor (-1 when closed), and whether `connect` succeeded and `close()` has not been called. `connected` does not change when the peer closes; use `peer_closed()`. |

When `connect` has several addresses to try, each gets the time left minus 1 s for every
address behind it, but at least 1 s (or whatever remains). With under 1 s left, an address
that has others behind it gets two thirds of what remains.

### Ownership

A `TcpSocket` closes its file descriptor when it is destroyed, and Mojo destroys a value
right after its last use. To hand the descriptor to something else, such as a
`TlsSocket`, take it with `detach()`. The new owner closes it:

```mojo
var tcp = TcpSocket()
tcp.connect(host, 443)
var tls = TlsSocket(tcp.detach())     # not TlsSocket(tcp.fd): tcp would close it
tls.connect(host, load_system_ca_bundle())
```

Before 2.0.0 nothing closed a dropped socket, so callers passed `tcp.fd`. That code
must switch to `detach()`.

### Errors

Every failure raises an `Error` with the reason:

- `tcp: cannot resolve <host>: <resolver message>`
- `tcp: cannot connect to <host>:<port> (<address>: <reason>; ...)`, one entry per
  address tried, such as `Connection refused` or `timed out`
- `tcp: send timed out (<sent> of <total> bytes sent)`, `tcp: recv timed out`
- `tcp: response exceeds maximum size of <n> bytes`, from `recv_all`
- `tcp: connection closed by peer`, `tcp: connection reset by peer`
- `connection to private/reserved IP address blocked (SSRF protection): ...`

Writing to a connection the peer has closed raises an error and never kills the
process. SIGPIPE is suppressed with `MSG_NOSIGNAL` on Linux and `SO_NOSIGPIPE` on macOS.

### TCP_NODELAY

Sockets connect with `TCP_NODELAY`, as libpq and Go do, so a small write goes out at
once instead of waiting for the previous one to be acknowledged (Nagle's algorithm).
On Linux (GitHub Actions, loopback), a request sent in five small writes took:

| | `TCP_NODELAY` (default) | `nodelay=False` |
|---|---|---|
| server that replies once per request (PostgreSQL's extended query, HTTP) | 56 us | 40,590 us (delayed-ACK stall) |
| server that answers every segment with its own small write, Nagle on its side | 22,957 us | 48 us |

macOS showed no stall in either case. The second row is a stall on the peer's side: such
a peer should set `TCP_NODELAY` itself, or the client can pass `nodelay=False` or send
each message in one write.

### SSRF protection

With `reject_private_ips=True`, addresses that are not globally reachable are skipped,
and the call raises if none is left. The check runs on the resolved addresses, the same
ones the socket connects to, so DNS tricks cannot bypass it.

- IPv4: every special-purpose range in RFC 6890: 0/8, 10/8, 100.64/10, 127/8,
  169.254/16 (cloud metadata), 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24,
  192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, and 224/4 and above (multicast,
  reserved, broadcast).
- IPv6: `::`, `::1`, fc00::/7, fe80::/10, fec0::/10, ff00::/8, 100::/64, 100:0:0:1::/64,
  2001::/23 (including Teredo), 2001:db8::/32, 3fff::/20, 5f00::/16 and 64:ff9b:1::/48.
  Addresses that embed an IPv4 address (`::ffff:a.b.c.d`, `::ffff:0:a.b.c.d`, NAT64
  `64:ff9b::/96`, 6to4 `2002::/16`) are judged by that address.

## Using tcp with other code

A Mojo program may declare each C function with only one signature, so two libraries
that declare the same one fail to compile together. tcp avoids every C function the
standard library declares (`open`, `read`, `write`, `fcntl`, errno access, `getenv`), so
it works next to `open()`, `std.os` and `std.time`; `test_std_compat.mojo` checks this.
Its socket calls use the same signatures as tls, so the two work together
(`tls/tests/test_ffi_compat.mojo`).

## Performance

`pixi run bench` runs both clients against the same loopback peers (`bench_peer.py`): tcp
(`bench_tcp.mojo`) and Python's `socket` module (`bench_client.py`). Apple M1 Pro, tcp 2.2.0,
ranges over five tcp runs and four Python runs.

| | tcp | Python sockets |
|---|---|---|
| send, 1 MiB chunks | 7.4-8.8 GB/s | 8.4-9.1 GB/s |
| receive loop, 64 KiB reads | 8.5-10.2 GB/s | 9.1-12.4 GB/s |
| `recv_all`, 256 MiB | 5.1-5.4 GB/s | |
| `recv_bytes_exact`, 5 + 59 bytes | 0.8 us/message | |
| request/response, 64 bytes | 22-25 us | 23.4-23.7 us |
| connect + close | 65-68 us | 66-69 us |

The two clients are level within the run-to-run spread. Both are limited by the kernel and
memory bandwidth, because Python's `socket` module is a thin wrapper over the same system
calls. Receives land directly in the returned list, with no intermediate buffer. `recv_all`
is slower than a receive loop because it keeps everything and pays for fresh memory.
From 4 MiB on it reserves room for its whole size limit (at most 128 MiB) in one step
instead of doubling, so it copies the data once.

## Development

```bash
pixi run test            # local tests (starts test_peer.py) + security tests + std compatibility; run in CI
pixi run test-security   # attack-shaped tests (9): SSRF spellings and embedded IPv4, descriptor leaks, caps, timeouts
pixi run fuzz            # fuzzers (fuzz/): bash fuzz/run.sh [iterations=150] [seed ...]; run in CI
pixi run test-tcp-live   # example.com and an IPv6-only host (needs the network)
pixi run bench           # loopback benchmarks: tcp and Python sockets (bench_tcp.mojo, bench_client.py, bench_peer.py)
```

### Security testing

- `test_security.mojo` holds the attack-shaped cases. Every host spelling that reaches
  loopback (`127.1`, `0x7f.1`, `2130706433`, ...) must be refused with
  `reject_private_ips`, and so must NUL, CRLF or junk in a host and an embedded internal
  IPv4 in any IPv6 form. 300 failed connects must not leak a descriptor, `recv_all` must
  stop at its cap, and timeouts are read back from the kernel with `getsockopt`.
- `fuzz/fuzz_ssrf.mojo` classifies random addresses, biased to range edges and to every
  embedded-IPv4 form. `fuzz/ref_ssrf.py` checks each verdict against the IANA
  special-purpose registries, written out independently of `tcp.mojo`. It fails when an
  address that is not globally reachable is allowed, or a public one is blocked.
- `fuzz/fuzz_io.mojo` calls every public operation with random and extreme arguments
  against a hostile peer (`fuzz/fuzz_peer.py`: resets, half-closes, floods, dribbles,
  silence). A crash or hang fails it, and so does a broken invariant: a result larger
  than asked, a timeout the kernel does not hold, `reject_private_ips` connecting to
  loopback, a leaked descriptor. A failure prints the command that reproduces it.
- CI runs the fuzzers on every pull request (`fuzz.yml`, fixed seeds) and on Sundays
  with a random seed. Each check was confirmed by mutation: a deliberate leak, a
  bypassed filter, a deleted range or a wrong `poll_fds` result makes it fail.

## License

MIT, see [LICENSE](LICENSE).
