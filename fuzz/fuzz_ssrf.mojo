# fuzz_ssrf.mojo — prints tcp's SSRF verdict for many generated addresses, one
# per line, for ref_ssrf.py to check against an independent reference:
#     4 a.b.c.d 1        (1 = blocked as private/special-purpose, 0 = allowed)
#     6 <32 hex digits> 0
# Usage: fuzz_ssrf <iterations> <seed>
# Addresses are biased to range edges (one off a boundary, embedded IPv4 in
# every form the filter unwraps) because that is where a filter is wrong.

from std.sys import argv
from tcp import _addr_v4, _addr_v6, _is_private_addr


struct Rng(Movable):
    var s: UInt64
    var edge: List[Int]   # octets next to the edges of every special-purpose IPv4 range
    var p6: List[Int]     # IPv6 leading groups at range edges

    def __init__(out self, seed: UInt64):
        self.s = seed if seed != 0 else UInt64(88172645463325252)
        self.edge = [
            0, 1, 2, 3, 8, 9, 10, 11, 15, 16, 17, 31, 32, 50, 51, 52, 63, 64, 65, 87, 88,
            89, 98, 99, 100, 101, 112, 113, 114, 126, 127, 128, 167, 168, 169, 170, 171,
            172, 173, 191, 192, 193, 197, 198, 199, 202, 203, 204, 223, 224, 225, 239,
            240, 241, 254, 255,
        ]
        self.p6 = [
            0x0000, 0x0064, 0x0100, 0x2001, 0x2002, 0x2003, 0x2600, 0x2a00, 0x3fff,
            0x4000, 0x5f00, 0x5f01, 0xfb00, 0xfc00, 0xfd00, 0xfe00, 0xfe7f, 0xfe80,
            0xfebf, 0xfec0, 0xfeff, 0xff00, 0xff02, 0x3ffe, 0x2000,
        ]

    def next(mut self) -> Int:
        self.s ^= self.s << 13
        self.s ^= self.s >> 7
        self.s ^= self.s << 17
        return Int(self.s >> 1)


def _hex2(v: Int) -> String:
    var d = String("0123456789abcdef")
    var b = d.as_bytes()
    return String(unsafe_from_utf8=[b[(v >> 4) & 15], b[v & 15]])


def _octet(mut r: Rng) -> Int:
    if r.next() % 3 == 0:
        return r.next() % 256
    return r.edge[r.next() % len(r.edge)]


def _emit_v4(a: Int, b: Int, c: Int, d: Int) -> String:
    var addr = _addr_v4(a, b, c, d, 80)
    return "4 " + String(a) + "." + String(b) + "." + String(c) + "." + String(d) + " " + (
        "1" if _is_private_addr(addr) else "0"
    )


def _emit_v6(bytes: List[UInt8]) -> String:
    var hex = String("")
    for i in range(16):
        hex += _hex2(Int(bytes[i]))
    var addr = _addr_v6(bytes, 80)
    return "6 " + hex + " " + ("1" if _is_private_addr(addr) else "0")


def _v6_case(mut r: Rng) -> List[UInt8]:
    var b = List[UInt8](length=16, fill=0)
    var kind = r.next() % 10
    if kind <= 2:
        # prefix from the edge table, then random groups
        var g0 = r.p6[r.next() % len(r.p6)]
        b[0] = UInt8(g0 >> 8)
        b[1] = UInt8(g0 & 255)
        for i in range(2, 16):
            if r.next() % 2 == 0:
                b[i] = UInt8(r.next() % 256)
    elif kind == 3:
        # IPv4-mapped ::ffff:a.b.c.d
        b[10] = 0xFF
        b[11] = 0xFF
        for i in range(12, 16):
            b[i] = UInt8(_octet(r))
    elif kind == 4:
        # IPv4-compatible ::a.b.c.d
        for i in range(12, 16):
            b[i] = UInt8(_octet(r))
    elif kind == 5:
        # NAT64 64:ff9b::/96 and 64:ff9b:1::/48
        b[1] = 0x64
        b[2] = 0xFF
        b[3] = 0x9B
        if r.next() % 3 == 0:
            b[5] = 0x01
            for i in range(6, 16):
                b[i] = UInt8(r.next() % 256)
        else:
            for i in range(12, 16):
                b[i] = UInt8(_octet(r))
    elif kind == 6:
        # 6to4 2002:AABB:CCDD::
        b[0] = 0x20
        b[1] = 0x02
        for i in range(2, 6):
            b[i] = UInt8(_octet(r))
        for i in range(6, 16):
            if r.next() % 2 == 0:
                b[i] = UInt8(r.next() % 256)
    elif kind == 7:
        # IPv4-translated ::ffff:0:a.b.c.d
        b[8] = 0xFF
        b[9] = 0xFF
        for i in range(12, 16):
            b[i] = UInt8(_octet(r))
    elif kind == 8:
        # 100:0:0:1::/64 dummy prefix
        b[1] = 0x01
        b[7] = 0x01
        for i in range(8, 16):
            b[i] = UInt8(r.next() % 256)
    else:
        for i in range(16):
            b[i] = UInt8(r.next() % 256)
    return b^


def main() raises:
    var args = argv()
    var iters = 100000
    var seed = UInt64(1)
    if len(args) > 1:
        iters = Int(args[1])
    if len(args) > 2:
        seed = UInt64(Int(args[2]))
    var r = Rng(seed)
    for _ in range(iters):
        if r.next() % 2 == 0:
            print(_emit_v4(_octet(r), _octet(r), _octet(r), _octet(r)))
        else:
            print(_emit_v6(_v6_case(r)))
