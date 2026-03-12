# ============================================================================
# test_tcp.mojo — Tests for TCP Socket Layer
# ============================================================================

from tcp import TcpSocket


fn test_connect_and_recv() raises:
    """Test basic TCP connection to httpbin.org:80 and raw HTTP exchange."""
    var sock = TcpSocket()
    sock.connect("httpbin.org", 80)

    # Send a raw HTTP GET request
    var request = (
        "GET /get HTTP/1.1\r\n"
        "Host: httpbin.org\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    var sent = sock.send(request)
    if sent <= 0:
        sock.close()
        raise Error("send returned " + String(sent))

    # Receive the full response
    var response_bytes = sock.recv_all()
    sock.close()

    if len(response_bytes) == 0:
        raise Error("received 0 bytes")

    # Convert to string for inspection
    var response = String(unsafe_from_utf8=response_bytes^)
    print("    Received", len(response), "bytes")

    # Check for HTTP response
    if len(response) < 12:
        raise Error("response too short")

    # Check starts with "HTTP/1.1"
    var resp_bytes = response.as_bytes()
    var check_bytes = List[UInt8]()
    for i in range(8):
        check_bytes.append(resp_bytes[i])
    var prefix_str = String(unsafe_from_utf8=check_bytes^)
    if prefix_str != "HTTP/1.1" and prefix_str != "HTTP/1.0":
        raise Error("expected HTTP response, got: " + prefix_str)


fn test_connect_failure() raises:
    """Test that connecting to an invalid host raises an error."""
    var sock = TcpSocket()
    var raised = False
    try:
        sock.connect("this-host-does-not-exist-12345.invalid", 80)
    except:
        raised = True
    if not raised:
        sock.close()
        raise Error("expected connection error for invalid host")


fn test_send_recv_localhost() raises:
    """Test connecting to localhost (skipped if nothing is listening)."""
    # This test is informational — it may skip if no local server is running
    var sock = TcpSocket()
    try:
        sock.connect("127.0.0.1", 18080)
        var sent = sock.send(
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        if sent > 0:
            var data = sock.recv_all()
            print("    Localhost response:", len(data), "bytes")
        sock.close()
    except:
        print("    (skipped - no server on localhost:18080)")


# ============================================================================
# Test Runner
# ============================================================================


fn main() raises:
    var passed = 0
    var failed = 0

    fn run_test(
        name: String,
        mut passed: Int,
        mut failed: Int,
        test_fn: fn () raises -> None,
    ):
        try:
            test_fn()
            print("  PASS:", name)
            passed += 1
        except e:
            print("  FAIL:", name, "-", String(e))
            failed += 1

    print("=== TCP Socket Tests ===")
    print()

    run_test(
        "connect and recv (httpbin.org)", passed, failed, test_connect_and_recv
    )
    run_test(
        "connect failure (invalid host)", passed, failed, test_connect_failure
    )
    run_test("send/recv localhost", passed, failed, test_send_recv_localhost)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
