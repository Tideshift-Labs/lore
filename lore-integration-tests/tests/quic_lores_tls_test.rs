// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// WP-124 slice 4: a managed `Put` over `lores://` (TLS on both legs) on a strict server.
//
// Its own test binary (`[[test]] name = "lores_tls"`), not a module of `integration`, because the
// storage clients have no CA setting (`custom_ca` is `None` in `quic/storage_service/auth.rs`).
// They trust the webpki roots plus the platform store, and `rustls-native-certs` replaces the
// platform store with `SSL_CERT_FILE` when that variable is set, on every platform. The only way to
// make a client trust a test CA is therefore a process-wide environment variable, and a binary of
// its own keeps it from every other suite.
//
// How the variable is set safely: by a constructor, before `main`, exactly as `integration.rs`
// sets its sandbox paths. At that point the process has one thread, so no Rust or C code can be
// reading the environment while it is written (C `getenv` takes no lock that `std::env::set_var`
// could take, which is why a write from inside a test, with the test harness and tokio threads
// alive, is not safe). Nothing in this binary writes the environment after that.
//
// What it proves: a strict server with a certificate on BOTH legs (the gRPC leg resolves the
// environment) admits a managed `Put` over `lores://` on a declared session, and refuses the same
// `Put` undeclared. The control proves the QUIC certificate is verified: the same shape of cell
// with a QUIC certificate outside the trusted CA is refused, no command reaches it, and the
// client's own debug log names the certificate failure (the returned error is a bare
// `Disconnected`: `connect` in `quic/client.rs` logs the cause and drops it).
#[cfg(all(test, feature = "integration_tests"))]
#[allow(dead_code)]
mod common;
#[cfg(all(test, feature = "integration_tests"))]
mod quic_managed_write_support;

#[cfg(all(test, feature = "integration_tests"))]
pub fn setup_execution(
    user_id: String,
) -> std::sync::Arc<lore_revision::interface::ExecutionContext> {
    std::sync::Arc::new(lore_revision::interface::ExecutionContext::new_server(
        lore_revision::interface::LoreGlobalArgs::default(),
        lore_revision::relay::EventDispatcher::no_dispatch(),
        user_id,
    ))
}

/// Points this binary's global config, credentials and service socket at names of its own, as
/// `integration.rs` does for its binary.
#[cfg(all(test, feature = "integration_tests"))]
#[ctor::ctor]
fn sandbox_machine_settings() {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    let sandbox = std::env::temp_dir().join(format!("lore-lores-tls-tests-{unique}"));
    std::fs::create_dir_all(&sandbox)
        .unwrap_or_else(|error| panic!("creating the sandbox at {}: {error}", sandbox.display()));

    // Safety: constructors run before `main`, so this is the single-threaded window where writing
    // to the environment has no reader to race.
    unsafe {
        std::env::set_var("LORE_GLOBAL_PATH", &sandbox);
        std::env::set_var("LORE_AUTH_PATH", &sandbox);
        std::env::set_var(
            "LORE_SERVICE_SOCKET",
            format!("lore_service-tls-{}", &unique[..12]),
        );
    }
    tls::install_trusted_ca();
}

#[cfg(all(test, feature = "integration_tests"))]
mod tls {
    use std::error::Error;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;
    use std::sync::OnceLock;

    use crate::quic_managed_write_support::TlsFiles;

    /// A CA and a loopback leaf (SAN `127.0.0.1`) it signs.
    pub struct TlsChain {
        _dir: lore_base::test_util::TempDir,
        pub ca: PathBuf,
        pub leaf: TlsFiles,
    }

    pub fn generate_tls_chain() -> Result<TlsChain, Box<dyn Error>> {
        use rcgen::BasicConstraints;
        use rcgen::CertificateParams;
        use rcgen::IsCa;
        use rcgen::Issuer;
        use rcgen::KeyPair;
        use rcgen::KeyUsagePurpose;
        use rcgen::SanType;

        let ca_key = KeyPair::generate()?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate()?;
        let mut leaf_params = CertificateParams::new(Vec::<String>::new())?;
        leaf_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;

        let dir = lore_base::test_util::TempDir::new("lore-managed-quic-tls-");
        let ca = dir.path().join("ca.pem");
        let cert = dir.path().join("leaf.pem");
        let key = dir.path().join("leaf.key");
        std::fs::write(&ca, ca_cert.pem())?;
        std::fs::write(&cert, leaf_cert.pem())?;
        std::fs::write(&key, leaf_key.serialize_pem())?;
        Ok(TlsChain {
            _dir: dir,
            ca,
            leaf: TlsFiles { cert, key },
        })
    }

    static TRUSTED: OnceLock<Result<TlsChain, String>> = OnceLock::new();

    /// Generate the one CA the clients trust and point `SSL_CERT_FILE` at it. Called only from the
    /// constructor in the crate root, before `main`.
    pub fn install_trusted_ca() {
        let chain = generate_tls_chain().map_err(|error| error.to_string());
        if let Ok(chain) = &chain {
            // Safety: called from a constructor, before `main` (see the crate root's header).
            unsafe { std::env::set_var("SSL_CERT_FILE", &chain.ca) };
        }
        let _ = TRUSTED.set(chain);
    }

    pub fn trusted_chain() -> Result<&'static TlsChain, String> {
        TRUSTED
            .get()
            .ok_or_else(|| "the trusted CA was never installed".to_string())?
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Every debug log line the transport emitted, for the control to read the failure cause from.
    pub static LOG: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

    pub fn capture(_level: lore_base::log::LoreLogLevel, _location: &str, message: &str) {
        if let Ok(mut log) = LOG.lock() {
            log.push(message.to_string());
        }
    }
}

#[cfg(all(test, feature = "integration_tests"))]
mod quic_lores_tls_tests {
    use std::sync::atomic::Ordering;

    use lore_revision::fragment;
    use lore_revision::lore::RepositoryId;
    use lore_transport::error::is_unsupported_client;
    use lore_transport::quic::storage_service::Command;
    use lore_transport::with_caller_operation;
    use rand::random;

    use crate::quic_managed_write_support::TestResult;
    use crate::quic_managed_write_support::Wire;
    use crate::quic_managed_write_support::cell;
    use crate::quic_managed_write_support::connect;
    use crate::quic_managed_write_support::in_context;
    use crate::quic_managed_write_support::managed;
    use crate::quic_managed_write_support::stored;
    use crate::tls;

    /// A managed `Put` over `lores://` on a strict server with TLS on both legs is admitted on a
    /// declared session. The same `Put` outside a scope is refused (status 200, typed), so the
    /// admission is the declaration's.
    #[tokio::test]
    async fn a_managed_put_over_lores_is_admitted_on_a_declared_session_when_the_ca_is_trusted()
    -> TestResult {
        let chain = tls::trusted_chain()?;
        in_context(async {
            let cell = cell(None, Some(chain.leaf.clone()), Some(chain.leaf.clone())).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lores", cell.port, partition).await?;
            let session = connection.session(partition, "lores-put").await?;
            let (fragment, address, payload) = fragment::generate_random();

            let refused = session
                .put(address, fragment, Some(payload.clone()))
                .await
                .expect_err("an undeclared Put over lores:// is refused by a strict server");
            assert!(is_unsupported_client(&refused), "{refused:?}");
            assert!(!stored(&cell.stores, partition, address).await);

            let (scope, journal) = managed(partition);
            with_caller_operation(
                scope.clone(),
                session.put(address, fragment, Some(payload.clone())),
            )
            .await?;
            assert_eq!(scope.declared_session_count(), 1);
            assert_eq!(journal.records.load(Ordering::SeqCst), 0);

            let puts: Vec<Wire> = cell
                .probe
                .wire()
                .into_iter()
                .filter(|w| w.opcode == Command::Put as u8)
                .collect();
            assert_eq!(puts.len(), 2, "{puts:?}");
            assert_eq!(cell.probe.declared_of(puts[0].session_id), Some(false));
            assert_eq!(
                cell.probe.declared_of(puts[1].session_id),
                Some(true),
                "the admitted Put ran on a declared session on the server"
            );
            assert!(stored(&cell.stores, partition, address).await);
            let (_, read) = session.get(&address).await?;
            assert_eq!(read, payload);
            Ok(())
        })
        .await
    }

    /// Control for the case above: the `lores://` client verifies the QUIC certificate. A server
    /// whose QUIC certificate the trusted CA does not cover is refused at the handshake, no command
    /// (not even an `Authorize`) reaches it, and the client's debug log names a certificate
    /// failure for this port. The gRPC leg here is the trusted one, so the refusal is the QUIC
    /// leg's.
    #[tokio::test]
    async fn a_lores_client_refuses_a_quic_certificate_the_trusted_ca_does_not_cover() -> TestResult
    {
        let trusted = tls::trusted_chain()?;
        let stranger = tls::generate_tls_chain()?;
        lore_base::log::set_log_callback(Some(tls::capture));
        lore_base::log::set_log_level(lore_base::log::LoreLogLevel::Debug);
        in_context(async {
            let cell = cell(
                None,
                Some(trusted.leaf.clone()),
                Some(stranger.leaf.clone()),
            )
            .await;
            let partition = random::<RepositoryId>();
            let outcome = async {
                let connection = connect("lores", cell.port, partition).await?;
                let session = connection.session(partition, "lores-untrusted").await?;
                let (scope, _journal) = managed(partition);
                let (fragment, address, payload) = fragment::generate_random();
                with_caller_operation(scope, session.put(address, fragment, Some(payload))).await
            }
            .await;
            assert!(
                outcome.is_err(),
                "a QUIC certificate outside the trusted CA must not be accepted"
            );
            assert!(
                cell.probe.wire().is_empty(),
                "the handshake is refused before any command: {:?}",
                cell.probe.wire()
            );

            // The cause, from the client's own log: the handshake for THIS port failed on the
            // peer certificate (rustls reports `invalid peer certificate: UnknownIssuer`).
            let port = cell.port.to_string();
            let log = tls::LOG.lock().expect("log mutex").clone();
            let failure = log.iter().find(|line| {
                line.contains("Failed QUIC connecting") && line.contains(&format!(":{port}"))
            });
            let failure = failure.unwrap_or_else(|| {
                panic!("no handshake failure was logged for port {port}: {log:?}")
            });
            assert!(
                failure.contains("certificate") || failure.contains("UnknownIssuer"),
                "the handshake failed, but not on the certificate: {failure}"
            );
            Ok(())
        })
        .await
    }
}
