# lore-object-dispatch

Server-only object-store dispatch authority primitives. The crate is dark source: it is not linked
into loreserver composition and cannot authorize provider traffic or first-seen admission.

## Continuity client

`continuity` connects directly to the independent object-dispatch continuity PostgreSQL authority.
It accepts exactly one TCP DNS host with `sslmode=require`, verifies that DNS name through rustls
against an explicit root CA, and requires a matching client certificate and private key. There is no
plaintext, opportunistic TLS, native-root, IP-host, Unix-socket, password-only, or insecure-verifier
mode. Connection and TLS material is redacted from diagnostics.

`ContinuityClient` exposes the versioned stored-procedure surface for:

- allocating or replaying an exact continuity intent;
- reading an intent by boundary and token;
- binding an intent to durable local state;
- marking exact completion evidence; and
- marking a decisive no-local-effect outcome and release basis.

Mutations run in serializable transactions. Unsigned 64-bit values cross the PostgreSQL
`NUMERIC(20,0)` boundary as canonical decimal text, procedure results decode through closed enum and
digest allowlists, and retry classification is limited to an explicit transport/SQLSTATE set. The
client does not retry operations itself.

## Embedded migration

`schema::CONTINUITY_MIGRATION_V1` embeds the exact 193,646-byte transactional migration used by the
independent authority. Its BLAKE3-256 is
`1530e511568b42b9368b1296eb6cdbaeecbc7f56a7838ac253bcbeb95434e6dd`. Runtime code never installs
the migration. Provisioning must install and read back separately attested bytes before readiness.

## Verification

```sh
cargo +nightly fmt --all -- --check
cargo clippy -p lore-object-dispatch --all-targets -- -D warnings --no-deps
cargo test -p lore-object-dispatch

# Explicit, disposable, preprovisioned PostgreSQL target only
cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_begin_replay_get_and_no_local_effect_cleanup
```

The unit suite validates configuration, TLS material, redaction, SQL procedure shapes, exact numeric
transfer, closed result decoding, migration identity, and transient-error classification. The
ignored live contract requires explicit environment variables and a disposable database; it covers
the real PostgreSQL 16 mTLS handshake, mapped boundary role, typed absence, serializable intent,
replay/readback, and no-local-effect release. Deployment readiness still requires reviewed
production BLAKE3 and typed validators, full cross-boundary negative isolation, timeout policy,
retry/reconciliation behavior, and deployment-revision readback.
