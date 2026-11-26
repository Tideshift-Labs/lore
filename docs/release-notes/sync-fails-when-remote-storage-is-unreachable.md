---
type: breaking
---

- `lore revision sync` to the branch latest now fails with `Disconnected` (exit 28) when the remote, or its storage,
  cannot be reached, instead of syncing against local history and saying "Already on branch ... latest". A sync with
  `--offline`, `--reset`, a view change or an explicit revision still runs against local history. Pass `--offline`
  to sync locally on purpose
- `lore revision sync`: a target revision whose state cannot be read because the remote is unreachable fails with
  `Disconnected` (exit 28), not an internal error (exit 255)
- Where no QUIC handshake with a `lore://` or `lores://` server completes, the client warns and the error names the
  host and UDP port, says a firewall or VPN may be blocking UDP, and names the `grpc://` or `grpcs://` URL to clone
  again over TCP. A clone or push that cannot reach the remote no longer reports "Repository not found"
- A process that already used QUIC to a server and then loses its UDP path (a VPN or firewall that starts dropping
  UDP mid-session) now fails a sync with the same `Disconnected` (exit 28) and hint after about 35 s (quinn's 30 s
  idle timeout plus one handshake), instead of after up to 120 s. A sync with nothing new to fetch fails the same
  way, rather than succeeding against local history without reaching storage. A QUIC reconnect's bound
  (`LORE_QUIC_RECONNECT_TIMEOUT`, default 30 s) now counts from when the path went silent, not from when the
  reconnect starts, with at least one handshake attempt; a server that returns within the bound is still reached
