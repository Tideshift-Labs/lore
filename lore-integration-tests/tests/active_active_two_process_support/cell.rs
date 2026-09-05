// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! One loreserver process: its rendered configuration, its lifecycle, and the
//! readiness surface the harness reads it through.
//!
//! Two of these run per case, on distinct ports and distinct state directories,
//! from the same release binary, against the same database and bucket. The only
//! other differences are the relay `owner` and the `producer_instance_id`, both
//! of which have to differ so a claim can be attributed and a publication
//! traced back to the process that made it.

use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use super::Env;
use super::toml_path;

/// The per-process configuration template, kept on disk as a reviewable
/// artefact rather than inlined, because it is the operator-facing shape of the
/// settings this whole proof depends on.
const TEMPLATE: &str =
    include_str!("../../fixtures/active-active-two-process/loreserver.toml.tmpl");

/// Substitute every `{{TOKEN}}`, and refuse to return a document that still
/// contains one.
///
/// A leftover placeholder is not a cosmetic defect: `bucket = "{{S3_BUCKET}}"`
/// boots a server that HEADs a bucket named `{{S3_BUCKET}}`, and the resulting
/// failure looks like missing infrastructure rather than a harness fault.
fn render(pairs: &[(&str, String)]) -> String {
    let mut rendered = TEMPLATE.to_owned();
    for (token, value) in pairs {
        rendered = rendered.replace(&format!("{{{{{token}}}}}"), value);
    }
    assert!(
        !rendered.contains("{{"),
        "the rendered loreserver configuration still contains a placeholder; \
         the harness and the template have drifted"
    );
    rendered
}

/// What the `/event_readiness` route reports, as far as this proof reads it.
///
/// Deliberately a partial mirror: pinning the whole body here would make an
/// unrelated field addition a harness failure, and the facets below are the
/// ones CR-032 and WP-109 name.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EventReadiness {
    pub configured: bool,
    pub relay_ready: bool,
    pub event_ready: bool,
    pub loop_running: bool,
    pub pending_count: i64,
    pub dead_letter_count: i64,
    /// This process's own durable-receiver facet.
    ///
    /// `None` when this process runs no receiver at all, which is every boot
    /// with the relay disabled: the receiver consumes on the relay's pool and
    /// channel, so loreserver refuses to start with one declared and no relay.
    pub receiver_ready: Option<bool>,
    /// Why that facet is false, from the receiver's own closed reason set.
    /// Carried so a stuck receiver names its own boundary in the failure
    /// message rather than timing out anonymously.
    #[serde(default)]
    pub receiver_reason: Option<String>,
    /// The membership generation the receiver is running.
    #[serde(default)]
    pub receiver_generation: Option<i64>,
}

/// The two things a case varies between boots of one process.
///
/// Kept together so a restart cannot silently carry one of them forward: a
/// restart meaning to drop a failpoint that also dropped the relay would turn a
/// recovery proof into a vacuous one.
#[derive(Debug, Clone, Copy)]
pub struct BootOptions<'a> {
    /// Whether `[outbox_relay] enabled` is true for this boot.
    pub relay_enabled: bool,
    /// `LORE_FRAGMENT_FAILPOINTS` for this boot, if any.
    pub failpoints: Option<&'a str>,
}

impl BootOptions<'_> {
    /// The ordinary shape: relay on, no injected fault.
    pub fn relaying() -> Self {
        Self {
            relay_enabled: true,
            failpoints: None,
        }
    }

    /// Relay off.
    ///
    /// The outbox still receives rows — appending happens inside the mutation's
    /// own transaction, not in the relay — so this is how a case produces a row
    /// that provably nothing has yet tried to claim.
    pub fn quiet() -> Self {
        Self {
            relay_enabled: false,
            failpoints: None,
        }
    }
}

/// A single loreserver process under harness control.
pub struct Cell {
    pub name: &'static str,
    pub grpc_port: u16,
    pub http_port: u16,
    config_dir: PathBuf,
    log_path: PathBuf,
    server_bin: PathBuf,
    /// Everything the template needs except the relay switch, which changes per
    /// boot and is therefore applied at render time rather than stored.
    render_pairs: Vec<(&'static str, String)>,
    /// Process environment except `LORE_FRAGMENT_FAILPOINTS`, same reason.
    base_env: Vec<(String, String)>,
    child: Option<Child>,
}

impl Cell {
    /// Render this process's configuration and start it.
    pub async fn start(
        env: &Env,
        name: &'static str,
        grpc_port: u16,
        http_port: u16,
        jwks_url: &str,
        auth_url: &str,
        options: BootOptions<'_>,
    ) -> Self {
        let config_dir = env.work_dir.join(format!("cell-{name}"));
        std::fs::create_dir_all(&config_dir).expect("create the process config directory");
        let state_dir = env.work_dir.join(format!("state-{name}"));
        std::fs::create_dir_all(&state_dir).expect("create the process state directory");

        let render_pairs = vec![
            ("GRPC_PORT", grpc_port.to_string()),
            ("HTTP_PORT", http_port.to_string()),
            ("PG_URL", env.pg_url.clone()),
            ("S3_BUCKET", env.s3_bucket.clone()),
            ("S3_ENDPOINT", env.s3_endpoint.clone()),
            ("S3_REGION", env.s3_region.clone()),
            ("JWKS_URL", jwks_url.to_owned()),
            // Both processes point at ONE stub. That is the point: a governed
            // mutation admitted through process A and a receipt read through
            // process B must be authorized by the same authority, or the proof
            // would be about two cells rather than one.
            ("AUTH_URL", auth_url.to_owned()),
            ("JWT_ISSUER", env.jwt_issuer.clone()),
            ("JWT_AUDIENCE", env.jwt_audience.clone()),
            ("GATEWAY_URI", env.gateway_uri.clone()),
            ("CELL_ID", env.cell_id.clone()),
            ("PLACEMENT_EPOCH", env.placement_epoch.to_string()),
            (
                "PRODUCER_INSTANCE_ID",
                format!("wp109-two-process-{name}-{grpc_port}"),
            ),
            ("STATE_DIR", toml_path(&state_dir)),
            ("CLIENT_CERT", toml_path(&env.client_cert)),
            ("CLIENT_KEY", toml_path(&env.client_key)),
            ("TRUST_ROOTS", toml_path(&env.trust_roots)),
            ("RELAY_OWNER", format!("wp109-relay-{name}-{grpc_port}")),
            // Two namespaces, and both are load-bearing.
            //
            // The gRPC port separates CASES within a run. The gateway keeps a
            // process-lifetime, per-identity monotonic generation guard
            // (`admitGeneration`) and the runner starts ONE gateway for the
            // whole run, while every case gets a fresh database whose
            // generation counter restarts at one. Two cases sharing an identity
            // would leave the second one's receiver refused as
            // `STALE_MEMBERSHIP_GENERATION_V1` forever. Each case owns its own
            // ten-port band, so the port is that namespace.
            //
            // The run id separates RUNS. The gateway derives a durable
            // consumer's name from the cell, the receiver identity, and the
            // membership generation, and `capture_new` on a consumer that
            // already exists ATTACHES rather than recreating — by design, so
            // two gateway replicas serving one generation report one position.
            // But the broker's streams and consumers outlive a run while the
            // case database does not, so a second run reusing an identity at
            // generation 1 attaches to the FIRST run's consumer, is served only
            // what that consumer never acknowledged, and carries a permanent
            // gap below its first delivery. Its contiguous frontier then never
            // reaches the sequences this run published. Measured: a rerun's
            // case G sat at frontier 34 against an accepted sequence of 45
            // until it timed out.
            (
                "RECEIVER_IDENTITY",
                format!("wp109-recv-{name}-{grpc_port}-{}", env.run_id),
            ),
            ("RECEIVER_CERT", toml_path(&env.receiver_cert)),
            ("RECEIVER_KEY", toml_path(&env.receiver_key)),
            // Five seconds is the reviewed floor (`MIN_CLAIM_LEASE`). The
            // failover case has to outlive a lease and then observe the
            // reclaim, so the shortest legal lease is the one that keeps that
            // case from becoming a minutes-long wait.
            ("CLAIM_LEASE_SECONDS", "5".to_owned()),
            ("IDLE_INTERVAL_MILLIS", "200".to_owned()),
        ];

        let base_env = vec![
            ("AWS_ACCESS_KEY_ID".to_owned(), env.s3_access_key.clone()),
            (
                "AWS_SECRET_ACCESS_KEY".to_owned(),
                env.s3_secret_key.clone(),
            ),
            ("AWS_REGION".to_owned(), env.s3_region.clone()),
            ("AWS_DEFAULT_REGION".to_owned(), env.s3_region.clone()),
            ("RUST_LOG".to_owned(), "info".to_owned()),
            ("LORE_ENV".to_owned(), "local".to_owned()),
        ];

        let mut cell = Self {
            name,
            grpc_port,
            http_port,
            config_dir,
            log_path: state_dir.join("loreserver.log"),
            server_bin: env.server_bin.clone(),
            render_pairs,
            base_env,
            child: None,
        };
        cell.spawn(options);
        cell.wait_ready().await;
        cell
    }

    /// The relay owner this process claims outbox rows under.
    pub fn relay_owner(&self) -> String {
        self.rendered("RELAY_OWNER")
    }

    /// The membership identity this process's durable receiver joins under.
    ///
    /// The key every checkpoint row this process writes is scoped by, so an
    /// assertion about one process's receiver can never be satisfied by the
    /// other's.
    pub fn receiver_identity(&self) -> String {
        self.rendered("RECEIVER_IDENTITY")
    }

    /// The `[plugins.remote.receiver]` table for this boot, or a comment.
    ///
    /// Tied to `relay_enabled` because loreserver REFUSES to start with a
    /// receiver declared and no relay
    /// (`StartupRefusal::ReceiverWithoutRelay`): the receiver consumes on the
    /// relay's own Postgres pool and gateway channel. Cases D and E boot a
    /// process quiet on purpose, so an unconditional table would stop those
    /// processes from booting at all.
    ///
    /// The checkpoint cadence is deliberately far tighter than the shipped
    /// defaults (a second and 256 events). A proof that waits on a frontier
    /// reaching Postgres should wait on the receiver, not on a batching
    /// interval chosen for production write volume.
    fn receiver_block(
        relay_enabled: bool,
        receiver_identity: &str,
        receiver_cert: &str,
        receiver_key: &str,
    ) -> String {
        if !relay_enabled {
            return "# No [plugins.remote.receiver]: this boot runs no relay, and loreserver\n\
                    # refuses to start a receiver without one (the receiver consumes on the\n\
                    # relay's own pool and gateway channel)."
                .to_owned();
        }
        format!(
            "[plugins.remote.receiver]\n\
             membership_identity = \"{receiver_identity}\"\n\
             lifecycle_generation = 1\n\
             lag_readiness_threshold = 1024\n\
             checkpoint_interval_ms = 250\n\
             checkpoint_every_events = 1\n\
             idle_poll_ms = 100\n\
             client_cert_path = \"{receiver_cert}\"\n\
             client_key_path = \"{receiver_key}\""
        )
    }

    fn rendered(&self, token: &str) -> String {
        self.render_pairs
            .iter()
            .find(|(candidate, _)| *candidate == token)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("every rendered process substitutes {token}"))
    }

    fn spawn(&mut self, options: BootOptions<'_>) {
        let mut pairs = self.render_pairs.clone();
        pairs.push(("RELAY_ENABLED", options.relay_enabled.to_string()));
        pairs.push((
            "RECEIVER_BLOCK",
            Self::receiver_block(
                options.relay_enabled,
                &self.rendered("RECEIVER_IDENTITY"),
                &self.rendered("RECEIVER_CERT"),
                &self.rendered("RECEIVER_KEY"),
            ),
        ));
        std::fs::write(self.config_dir.join("local.toml"), render(&pairs))
            .expect("write the process configuration");

        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .expect("open the process log");
        let errors = log.try_clone().expect("duplicate the process log handle");
        let mut command = Command::new(&self.server_bin);
        command
            .arg("--config")
            .arg(&self.config_dir)
            .arg("--env")
            .arg("local")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(errors));
        for (key, value) in &self.base_env {
            command.env(key, value);
        }
        match options.failpoints {
            Some(spec) => {
                command.env("LORE_FRAGMENT_FAILPOINTS", spec);
            }
            None => {
                command.env_remove("LORE_FRAGMENT_FAILPOINTS");
            }
        }
        let child = command.spawn().unwrap_or_else(|error| {
            panic!(
                "spawn loreserver from {}: {error}",
                self.server_bin.display()
            )
        });
        self.child = Some(child);
    }

    /// Wait until BOTH surfaces this harness uses are up, or fail with the log.
    ///
    /// The gRPC check is not redundant. `server.rs` spawns the gRPC and HTTP
    /// endpoints as separate tasks on one `JoinSet`, so an HTTP-only probe can
    /// report ready while the gRPC listener has not bound — and every case's
    /// first action is a gRPC call, which would then fail as `UNAVAILABLE` and
    /// be read as a server defect. A TCP connect is the weakest check that
    /// proves the listener exists; the alternative, a real RPC, would need a
    /// token and a repository this early.
    ///
    /// The log tail is in the panic on purpose. Every interesting boot failure
    /// here — an absent bucket, an unreachable JWKS, a refused relay startup
    /// gate — is reported by the process and nowhere else, and a bare "did not
    /// become ready" sends the reader to the wrong layer.
    pub async fn wait_ready(&mut self) {
        let url = format!("http://127.0.0.1:{}/event_readiness", self.http_port);
        let grpc = format!("127.0.0.1:{}", self.grpc_port);
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(child) = self.child.as_mut()
                && let Ok(Some(status)) = child.try_wait()
            {
                panic!(
                    "loreserver {} exited during boot with {status}\n--- log ---\n{}",
                    self.name,
                    self.log_tail()
                );
            }
            let http_up = reqwest::get(&url)
                .await
                .is_ok_and(|response| response.status().is_success());
            if http_up && tokio::net::TcpStream::connect(&grpc).await.is_ok() {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "loreserver {} never served both {url} and gRPC on {grpc} \
                     (http_up={http_up})\n--- log ---\n{}",
                    self.name,
                    self.log_tail()
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// The current `/event_readiness` body.
    ///
    /// Decoded from the response text rather than through `reqwest`'s `json`
    /// helper, so this harness does not widen the workspace's `reqwest` feature
    /// set for one call.
    pub async fn event_readiness(&self) -> EventReadiness {
        let url = format!("http://127.0.0.1:{}/event_readiness", self.http_port);
        let body = reqwest::get(&url)
            .await
            .unwrap_or_else(|error| panic!("read {url}: {error}"))
            .text()
            .await
            .unwrap_or_else(|error| panic!("read the {url} body: {error}"));
        serde_json::from_str(&body)
            .unwrap_or_else(|error| panic!("decode the {url} body ({body}): {error}"))
    }

    /// The plaintext h2c endpoint a gRPC client dials.
    pub fn grpc_endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.grpc_port)
    }

    /// Hard-kill the process and wait for the operating system to reap it.
    ///
    /// A kill, not a shutdown signal: a graceful stop drains the relay, which
    /// is precisely the behaviour the kill cases must not get.
    pub fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Whether the process has exited on its own.
    pub fn has_exited(&mut self) -> bool {
        match self.child.as_mut() {
            None => true,
            Some(child) => matches!(child.try_wait(), Ok(Some(_))),
        }
    }

    /// Wait until the process exits by itself, then reap it.
    ///
    /// Used by the failpoint-abort case, where ending the process is the
    /// injected fault rather than something the harness does from outside.
    pub async fn wait_exit(&mut self, within: Duration) {
        let deadline = Instant::now() + within;
        while !self.has_exited() {
            assert!(
                Instant::now() < deadline,
                "loreserver {} did not exit within {within:?}\n--- log ---\n{}",
                self.name,
                self.log_tail()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }

    /// Start the process again under different boot options.
    pub async fn restart_with(&mut self, options: BootOptions<'_>) {
        self.kill();
        self.spawn(options);
        self.wait_ready().await;
    }

    /// The last 8 KiB of the process log, for a failure message.
    pub fn log_tail(&self) -> String {
        let Ok(text) = std::fs::read_to_string(&self.log_path) else {
            return format!("(no log at {})", self.log_path.display());
        };
        let start = text.len().saturating_sub(8192);
        text[start..].to_owned()
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        self.kill();
    }
}
