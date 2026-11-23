# Changelog

Release history for tcp. The README describes the current behaviour.

## 2.2.0

Additive: every existing signature and behaviour is unchanged.

- Millisecond timeouts: `connect(..., timeout_ms=...)`, `set_timeout_ms(ms)`,
  `set_timeout(secs)` and `set_socket_timeout_ms(fd, ms)`. The socket options always
  took a `timeval`; the whole-second limit was ours. tls and requests now use this
  public setter instead of the private `_set_socket_timeouts`.
- SSRF filter: three IPv6 ranges that are not globally reachable were allowed and are
  now blocked: `5f00::/16` (SRv6 SIDs, RFC 9602), `3fff::/20` (documentation, RFC 9637)
  and `100:0:0:1::/64` (dummy prefix, RFC 9780). IPv4-translated addresses
  (`::ffff:0:a.b.c.d`, RFC 2765) are now judged by the IPv4 address they carry, so
  `::ffff:0:7f00:1` no longer passes as public. The new fuzzers found these.
- Polling: `poll_fds`, `set_nonblocking` and the `POLLIN`, `POLLOUT`, `POLLERR`,
  `POLLHUP` and `POLLNVAL` constants, the base for waiting on many sockets from one
  thread.

## 2.1.0

- Builds on Mojo 1.2.0 (the floor is now 1.2.0).

## 2.0.2

- `TCP_NODELAY` by default (`connect(..., nodelay=False)` to opt out).
- `peer_closed()`: a non-blocking check that the peer has not closed the connection.
- The README states that DNS resolution is not covered by `timeout_secs`.

## 2.0.1

- Receives are up to 4.5x faster (`recv_bytes` 1.6 to 7.1+ GB/s, `recv_all` 1.0 to
  2.2 GB/s) because data is received straight into the returned list.
- Bounded memory: `recv_bytes_exact(n)` no longer reserves `n` bytes before any data
  arrives (a server-supplied length could reserve gigabytes), and one `recv()` reads at
  most 1 MiB (lengths above 2 GiB failed with EINVAL).
- `timeout_secs` bounds the whole connect. Each address used to get the full timeout, so
  a name resolving to many unreachable addresses (8 took 8 s with `timeout_secs=1`)
  could hang a client for minutes.
- Very large `timeout_secs` values no longer overflow the poll timeout.

## 2.0.0

- Sockets close themselves when destroyed, and `detach()` hands the descriptor over.
  `connect()` on an open socket closes it first. This breaks code that passed `tcp.fd`
  (see Ownership).
- No more SIGPIPE: a write to a closed connection used to kill the process.
- `send` sends everything. It used to return a short count after a timeout, which
  callers ignored; it now finishes or raises. `send_bytes` was added.
- Connecting: IPv6, every resolved address in turn, and a connect timeout that also
  works on macOS (it used to wait about 75 s).
- SSRF protection covers all special-purpose ranges, including IPv6. It used to miss
  100.64/10, 198.18/15, 192.0.0/24, 224/4, 240/4 and broadcast.
- Errors give reasons, and ports and `recv_bytes(0)` are validated.
