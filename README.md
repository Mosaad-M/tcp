# tcp — Pure Mojo TCP Socket

A pure-[Mojo](https://www.modular.com/mojo) TCP socket layer using POSIX FFI.

## Features

- `TcpSocket` struct wrapping `socket()`, `connect()`, `send()`, `recv()`, `close()`
- DNS resolution via `getaddrinfo()` / `freeaddrinfo()`
- `recv_bytes` and `recv_bytes_exact` for binary data
- Includes `errno_helper.c` — a minimal C wrapper to expose `errno` to Mojo (compiler workaround for Mojo 0.26+)

## Usage

```mojo
from tcp import TcpSocket

var sock = TcpSocket()
sock.connect("example.com", 80)
sock.send("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n".as_bytes())
var response = sock.recv_bytes(4096)
sock.close()
```

## C Dependency

`errno_helper.c` must be compiled to `liberrno_helper.so` before use:

```bash
gcc -shared -fPIC -o liberrno_helper.so errno_helper.c
```

Or via pixi:

```bash
pixi run build-c
```

Link with `-Xlinker -lerrno_helper -Xlinker -L<path>` when building Mojo code.

## Requirements

- Mojo `>=0.26.1`
- GCC or Clang (to compile `errno_helper.c`)

## Testing

```bash
pixi run test-tcp
# 3/3 tests pass
```

## License

MIT — see [LICENSE](LICENSE)
