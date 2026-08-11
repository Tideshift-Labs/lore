# SPDX-FileCopyrightText: 2026 Khurram Virani
# SPDX-License-Identifier: MIT
"""Regression guard for `allocate_free_port`'s candidate generation.

The helper hands a port number to a server process that binds it for BOTH
gRPC (TCP) and QUIC (UDP). It used to source candidates from `bind(0)`, which
on Windows walks a machine-global cursor strictly +1 per call. Its 20-attempt
retry loop therefore probed 20 ADJACENT numbers, and Windows keeps a separate
UDP exclusion list whose bands (measured: 60-500 consecutive ports) are all
wider than that span. Land the cursor inside a band and every attempt failed
together with WSAEACCES (WinError 10013), persistently rather than flakily,
because each failure advanced the cursor by only 1.

These are pure unit tests: no server, no CLI, no network traffic beyond
loopback binds, so they run in milliseconds and are safe in the default suite.
"""

import socket

from lore_server import allocate_free_port

# Matches the sampling window in `allocate_free_port`.
DYNAMIC_LOW, DYNAMIC_HIGH = 49152, 65535


def test_returns_a_port_free_for_both_tcp_and_udp():
    """The whole point of the helper: one number, both protocols."""
    port = allocate_free_port()
    assert DYNAMIC_LOW <= port <= DYNAMIC_HIGH, (
        f"port {port} outside the sampled dynamic range [{DYNAMIC_LOW}, {DYNAMIC_HIGH}]"
    )

    # Re-bind both to confirm the number really was free for each. This is the
    # property a TCP-only probe cannot establish.
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        tcp.bind(("127.0.0.1", port))
        udp.bind(("127.0.0.1", port))
    finally:
        tcp.close()
        udp.close()


def test_candidates_are_not_drawn_sequentially():
    """The actual regression guard.

    The old `bind(0)` implementation produced strictly consecutive candidates,
    so N calls spanned exactly N-1 ports, which is why a single exclusion band
    could swallow every retry. Random sampling must not do that.

    Non-flaky by a wide margin: for 12 uniform draws from ~16k values to span
    12 or fewer, every draw has to land in one narrow window, which has
    probability on the order of 1e-30. A failure here means the candidate
    source went back to walking, not that we got unlucky.
    """
    calls = 12
    ports = [allocate_free_port() for _ in range(calls)]
    span = max(ports) - min(ports)
    assert span > calls, (
        f"candidates look sequential (span {span} across {calls} calls: "
        f"{ports}). `allocate_free_port` must sample independently, not walk "
        f"the ephemeral cursor, or one exclusion band swallows every retry"
    )
