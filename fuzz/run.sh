#!/bin/bash
# Fuzzers for tcp: the SSRF filter against an independent reference, and every
# public socket operation against a hostile peer.
# Usage: bash fuzz/run.sh [iterations=150] [seed ...]   (seeds default to 1 2 3)
#   fuzz_ssrf  iterations x 2000 addresses per seed, checked by ref_ssrf.py
#   fuzz_io    iterations connections per seed against fuzz_peer.py (port 19501)
# A crash (abort, memory fault, hang) or a broken invariant fails the run and
# prints the command that reproduces it.
set -o pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ITERS="${1:-150}"
shift
SEEDS="${*:-1 2 3}"
mkdir -p .build
for f in fuzz_ssrf fuzz_io; do
    mojo build -I . "fuzz/$f.mojo" -o ".build/$f" || exit 1
done

FAILED=0
for seed in $SEEDS; do
    # perl alarm: macOS has no timeout(1)
    if ! perl -e 'alarm 600; exec @ARGV' .build/fuzz_ssrf $((ITERS * 2000)) "$seed" | python3 fuzz/ref_ssrf.py; then
        echo "FAIL: .build/fuzz_ssrf $((ITERS * 2000)) $seed | python3 fuzz/ref_ssrf.py   (reproduce: bash fuzz/run.sh $ITERS $seed)"
        FAILED=1
    fi
done

python3 fuzz/fuzz_peer.py 1 &
PEER=$!
trap 'kill $PEER 2>/dev/null' EXIT
sleep 1
if ! kill -0 $PEER 2>/dev/null; then
    echo "FAIL: fuzz_peer.py did not start (port 19501 busy?)"
    exit 1
fi
for seed in $SEEDS; do
    if ! perl -e 'alarm 600; exec @ARGV' .build/fuzz_io "$ITERS" "$seed" | tail -1; then
        echo "FAIL: .build/fuzz_io $ITERS $seed trace   (peer: python3 fuzz/fuzz_peer.py 1; reproduce: bash fuzz/run.sh $ITERS $seed)"
        FAILED=1
    fi
done
exit $FAILED
