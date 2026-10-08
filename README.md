# tcp

A TCP client socket for [Mojo](https://www.modular.com/mojo), written against POSIX
directly (no C helper, no dependencies). It is the transport under
[tls](https://github.com/Mosaad-M/tls), [requests](https://github.com/Mosaad-M/requests),
[websocket](https://github.com/Mosaad-M/websocket) and [pg](https://github.com/Mosaad-M/pg).

## Install

With [mojo-pkg](https://github.com/Mosaad-M/mojo-pkg):

```toml
[dependencies]
tcp = { git = "Mosaad-M/tcp", version = ">=2.0.0" }
```

Or clone the repository and build with `-I path/to/tcp`.
Mojo >= 1.0.0 on linux-64 or osx-arm64.

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
| `connect(host, port, reject_private_ips=False, timeout_secs=30, nodelay=True)` | Resolve `host` (name, IPv4 or IPv6 literal) and try each address, IPv4 first, until one connects. `timeout_secs` (0 = none) bounds the whole connect, across all addresses (the first address gets the timeout minus 1 s for each address after it, later ones at least 1 s each; DNS resolution is not included), and then every send and receive. DNS resolution is not covered: `getaddrinfo` uses the system resolver's own timeout. `nodelay` sets `TCP_NODELAY` (see below). Ports must be 1-65535. Connecting an open socket closes it first. |
| `send(data: String) -> Int`, `send_bytes(data: List[UInt8]) -> Int` | Send **all** of `data` and return its length. |
| `recv_bytes(max_bytes=4096) -> List[UInt8]` | Up to `max_bytes` (> 0; at most 1 MiB per call); empty means the peer closed. |
| `recv_bytes_exact(n)` | Exactly `n` bytes, or an error if the stream ends first. Memory grows with the bytes that arrive, so a large `n` from an untrusted peer reserves nothing up front (callers should still cap such lengths). |
| `recv_all(max_size=100 MB)` | Everything until the peer closes. |
| `recv(max_bytes) -> String` | Like `recv_bytes`, as a String (not checked to be UTF-8; prefer `recv_bytes`). |
| `peer_closed() -> Bool` | Whether the peer has closed or reset the connection (or the socket is not connected), without blocking or consuming data. Check it before reusing a pooled connection. |
| `detach() -> Int32` | Give up ownership of the file descriptor (see below). |
| `close()` | Shut down and close; safe to call twice. |
| `fd`, `connected` | The file descriptor (-1 when closed) and whether `connect` succeeded and `close()` has not been called. `connected` does not change when the peer closes; use `peer_closed()` for that. |

### Ownership

A `TcpSocket` closes its file descriptor when it is destroyed, and Mojo destroys a
value right after its last use. To hand the descriptor to something else, such as a
`TlsSocket`, take it with `detach()`. The new owner closes it:

```mojo
var tcp = TcpSocket()
tcp.connect(host, 443)
var tls = TlsSocket(tcp.detach())     # not TlsSocket(tcp.fd): tcp would close it
tls.connect(host, load_system_ca_bundle())
```

Before 2.0.0 nothing closed a dropped socket, so callers passed `tcp.fd`. Code like
that must switch to `detach()`.

### Errors

Every failure raises an `Error` whose message gives the reason:

- `tcp: cannot resolve <host>: <resolver message>`
- `tcp: cannot connect to <host>:<port> (<address>: <reason>; ...)`: one entry per
  address tried, e.g. `Connection refused` or `timed out`
- `tcp: send timed out (<sent> of <total> bytes sent)`, `tcp: recv timed out`
- `tcp: connection closed by peer`, `tcp: connection reset by peer`
- `connection to private/reserved IP address blocked (SSRF protection): ...`

Writing to a connection the peer has closed raises an error and never kills the
process: SIGPIPE is suppressed with `MSG_NOSIGNAL` on Linux and `SO_NOSIGPIPE` on
macOS.

### TCP_NODELAY

Sockets are connected with `TCP_NODELAY` (as libpq and Go do), so a small write goes
out at once instead of waiting for the previous one to be acknowledged (Nagle's
algorithm). Protocols that send one message in several writes and then wait for the
reply (PostgreSQL's extended query sends five) can otherwise stall for a delayed ACK,
typically 40 ms on Linux. Pass `nodelay=False` to keep Nagle when many tiny writes
should be coalesced: on loopback, five 4-byte writes and an echo take ~90 us with
`TCP_NODELAY` and ~50 us without. (Against example.com from macOS, the same pattern
showed no stall either way, so the benefit depends on the platforms at both ends.)

### SSRF protection

With `reject_private_ips=True`, addresses that are not globally reachable are
skipped, and the call raises if none is left. The check runs on the resolved
addresses, the same ones the socket connects to, so DNS tricks cannot bypass it.

- **IPv4:** every special-purpose range in RFC 6890: 0/8, 10/8, 100.64/10, 127/8,
  169.254/16 (cloud metadata), 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24,
  192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, and 224/4 and above
  (multicast, reserved, broadcast).
- **IPv6:** `::`, `::1`, fc00::/7, fe80::/10, fec0::/10, ff00::/8, 100::/64,
  2001::/23 (including Teredo), 2001:db8::/32 and 64:ff9b:1::/48. Addresses that
  embed an IPv4 address (`::ffff:a.b.c.d`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`)
  are judged by that address.

## Performance

`pixi run bench` (loopback, Apple M1 Pro, `bench_peer.py` as the peer):

| | tcp 2.0.1 | tcp 2.0.0 | Python sockets |
|---|---|---|---|
| send, 1 MiB chunks | 6.2-8.0 GB/s | 7.4-8.0 GB/s | 8.3 GB/s |
| `recv_bytes(64 KiB)` loop | 7.1-7.7 GB/s | 1.6 GB/s | 8.6 GB/s |
| `recv_all`, 256 MiB | 2.2 GB/s | 1.0 GB/s | |
| `recv_bytes_exact`, 5 + 59 bytes | 1.1 us/message | 1.5 us | |
| request/response, 64 bytes | 28 us | 28 us | 28 us |
| connect + close | 70-85 us | 70-88 us | 109 us |

Receives land directly in the returned list (no intermediate buffer or byte-by-byte
copy). `recv_all` is slower than a `recv_bytes` loop because it keeps everything:
the cost is fresh memory and the copy when its buffer doubles.

## Development

```bash
pixi run test            # local tests (starts test_peer.py) + std compatibility; run in CI
pixi run test-tcp-live   # example.com and an IPv6-only host (needs the network)
pixi run bench           # loopback benchmarks (bench_tcp.mojo + bench_peer.py)
```

tcp declares no C function that Mojo's standard library also declares
(`open`/`read`/`write`, `fcntl`, errno access, `getenv`, ...), so it works next to
`open()`, `std.os` and `std.time` (`test_std_compat.mojo`). Its socket calls use the
same signatures as tls (`tls/tests/test_ffi_compat.mojo`).

## Changes in 2.0.2

- **`TCP_NODELAY` by default** (`connect(..., nodelay=False)` to opt out).
- **`peer_closed()`**: a non-blocking check that the peer has not closed the connection.
- The README states that DNS resolution is not covered by `timeout_secs`.

## Changes in 2.0.1

- **Receives are up to 4.5x faster** (`recv_bytes` 1.6 to 7.1+ GB/s, `recv_all` 1.0 to
  2.2 GB/s): data is received straight into the returned list.
- **Bounded memory:** `recv_bytes_exact(n)` no longer reserves `n` bytes before any data
  arrives (a server-supplied length could reserve gigabytes), and one `recv()` reads
  at most 1 MiB (lengths above 2 GiB failed with EINVAL).
- **`timeout_secs` bounds the whole connect.** Each address used to get the full timeout,
  so a name resolving to many unreachable addresses (8 took 8 s with
  `timeout_secs=1`) could hang a client for minutes.
- Very large `timeout_secs` values no longer overflow the poll timeout.

## Changes in 2.0.0

- **Sockets close themselves** when destroyed; `detach()` hands the descriptor over.
  `connect()` on an open socket closes it first. (Breaking: see Ownership.)
- **No more SIGPIPE.** A write to a closed connection used to kill the process.
- **`send` sends everything.** It used to return a short count after a timeout,
  which callers ignored; it now finishes or raises. `send_bytes` was added.
- **Connecting:** IPv6, every resolved address in turn, and a connect timeout
  that also works on macOS (it used to wait about 75 s).
- **SSRF protection** covers all special-purpose ranges, including IPv6. Before, it
  missed 100.64/10, 198.18/15, 192.0.0/24, 224/4, 240/4 and broadcast.
- **Errors give reasons**; ports and `recv_bytes(0)` are validated.

## License

MIT, see [LICENSE](LICENSE).
