#!/usr/bin/env python3
"""Reference for fuzz_ssrf: reads "4 a.b.c.d verdict" / "6 hex32 verdict" lines
(verdict 1 = tcp blocks the address) and checks them against the IANA
special-purpose registries, written out here so the check does not depend on
the Python version's ipaddress tables (which it also consults).

Fails (exit 1) when
  * tcp ALLOWS an address the registry says is not globally reachable
    (an SSRF bypass), or
  * tcp BLOCKS an address that is globally reachable and not in STRICTER
    (a public range wrongly blocked).
"""
import ipaddress
import sys

N = ipaddress.ip_network

# IANA IPv4 Special-Purpose Address Registry (not globally reachable) + multicast/reserved
V4_BLOCK = [N(x) for x in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)]
# Globally reachable addresses tcp blocks anyway (documented: all of 192.0.0/24 and 2001::/23)
V4_STRICTER = [N("192.0.0.9/32"), N("192.0.0.10/32")]

V6_BLOCK = [N(x) for x in (
    "::/128", "::1/128", "100::/64", "100:0:0:1::/64", "2001::/23", "2001:db8::/32",
    "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
    "64:ff9b:1::/48",
)]
V6_STRICTER = [N("2001:1::1/128"), N("2001:1::2/128")]


def in_any(ip, nets):
    return any(ip in n for n in nets)


def v4_non_global(ip):
    return in_any(ip, V4_BLOCK) or not ip.is_global and not in_any(ip, V4_STRICTER)


def embedded_v4(ip6):
    """The IPv4 address an IPv6 address stands for, or None."""
    b = ip6.packed
    if b[:10] == bytes(10) and b[10:12] == b"\xff\xff":
        return ipaddress.IPv4Address(b[12:])          # ::ffff:a.b.c.d
    if b[:12] == bytes(12) and b[12:] not in (bytes(4), b"\0\0\0\1"):
        return ipaddress.IPv4Address(b[12:])          # ::a.b.c.d (deprecated)
    if b[:12] == bytes.fromhex("0064ff9b0000000000000000"):
        return ipaddress.IPv4Address(b[12:])          # 64:ff9b::/96
    if b[:2] == b"\x20\x02":
        return ipaddress.IPv4Address(b[2:6])          # 6to4
    if b[:12] == bytes.fromhex("0000000000000000ffff0000"):
        return ipaddress.IPv4Address(b[12:])          # ::ffff:0:a.b.c.d (translated)
    return None


def expected_block(ip):
    """(non_global, stricter_ok): whether the registry says the address must be blocked."""
    if ip.version == 4:
        return v4_non_global(ip)
    e = embedded_v4(ip)
    if e is not None:
        return v4_non_global(e)
    return in_any(ip, V6_BLOCK) or (not ip.is_global and not in_any(ip, V6_STRICTER))


def main():
    bad = 0
    seen = 0
    for line in sys.stdin:
        parts = line.split()
        if len(parts) != 3:
            continue
        fam, text, verdict = parts
        ip = ipaddress.IPv4Address(text) if fam == "4" else ipaddress.IPv6Address(int(text, 16))
        got = verdict == "1"
        want = expected_block(ip)
        seen += 1
        if got == want:
            continue
        stricter = in_any(ip, V4_STRICTER if ip.version == 4 else V6_STRICTER)
        if got and not want and stricter:
            continue
        bad += 1
        if bad <= 20:
            what = "ALLOWED but not globally reachable" if want else "BLOCKED but globally reachable"
            print(f"MISMATCH {what}: {ip}  (embedded v4: {embedded_v4(ip) if ip.version == 6 else '-'})")
    print(f"ssrf reference: {seen} addresses, {bad} mismatch(es)")
    return 1 if bad else 0


sys.exit(main())
