# test_std_compat.mojo — tcp must not break programs that use Mojo's std
#
# A Mojo program may declare each C function with one signature only. std
# declares open/read/write, fcntl, close, strerror, errno access, getenv and
# clock_gettime itself, so tcp must declare none of those differently.
# Compiling this file is the test: it reaches every tcp code path that calls
# the OS, next to those std APIs. Running it exercises the std calls only.

from std.ffi import get_errno
from std.os import getenv, listdir
from std.sys import argv
from std.time import monotonic, perf_counter_ns
from tcp import TcpSocket


def network_paths() raises:
    """Never run: compiled so that tcp's C declarations are present."""
    var s = TcpSocket()
    s.connect("example.com", 80, reject_private_ips=True, timeout_secs=5)
    _ = s.send("x")
    _ = s.send_bytes(List[UInt8](length=1, fill=0))
    _ = s.recv(10)
    _ = s.recv_bytes(10)
    _ = s.recv_bytes_exact(1)
    _ = s.recv_all()
    var fd = s.detach()
    var t = TcpSocket()
    t.connect("example.com", 80)
    t.close()
    print(fd)


def main() raises:
    print("test_std_compat")
    if len(argv()) > 1000:
        network_paths()
    with open("/tmp/mojo_tcp_std_compat.txt", "w") as f:
        f.write("std open() next to tcp\n")
    with open("/tmp/mojo_tcp_std_compat.txt", "r") as f:
        if not f.read().startswith("std open()"):
            raise Error("std open()/read() round trip failed")
    _ = listdir("/tmp")
    _ = getenv("HOME")
    _ = get_errno()
    _ = perf_counter_ns() + monotonic()
    print("  PASS: TcpSocket compiles next to std open/listdir/getenv/get_errno/clocks")
    print("Results: 1 passed, 0 failed")
