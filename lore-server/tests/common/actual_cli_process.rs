// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Native CLI children with owned credentials, bounded wait, and panic-path reaping.
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use super::actual_cli_auth::AuthServer;
pub(super) struct Cli {
    root: PathBuf,
    authn: String,
    authz: String,
    sequence: usize,
}
impl Cli {
    pub fn new(root: &Path, auth: &AuthServer) -> Self {
        Self {
            root: root.into(),
            authn: auth.authn.clone(),
            authz: auth.authz.clone(),
            sequence: 0,
        }
    }
    pub async fn run(&mut self, step: &str, args: &[&str], cwd: &Path, auth_store: &str) -> String {
        let bin =
            std::env::var("LORE_TEST_ACTUAL_CLI").expect("runner must provide actual CLI binary");
        assert!(Path::new(&bin).is_file(), "actual CLI binary missing");
        self.sequence += 1;
        let path = self.root.join(format!("cli-{}-{step}.log", self.sequence));
        let file = std::fs::File::create(&path).unwrap();
        let mut command = std::process::Command::new(bin);
        command
            .args(["--no-pager", "--non-interactive", "--max-threads", "4"])
            .args(args)
            .current_dir(cwd)
            .env("LORE_AUTH_PATH", self.root.join(auth_store))
            .env(
                "LORE_GLOBAL_PATH",
                self.root.join(auth_store).join("global"),
            )
            .env("LORE_AUTH_STORE", "fallback")
            .env_remove("LORE_USE_SERVICE")
            .env(
                "SSL_CERT_FILE",
                std::env::var("LORE_TEST_CLEAN_INIT_CA_PATH").unwrap(),
            )
            .env_remove("SSL_CERT_DIR")
            .stdin(std::process::Stdio::null())
            .stdout(file.try_clone().unwrap())
            .stderr(file);
        let mut child = Child(command.spawn().expect("spawn actual native CLI"));
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.0.kill().unwrap();
                child.0.wait().unwrap();
                let output = std::fs::read_to_string(&path).unwrap();
                assert!(
                    !output.contains(&self.authn) && !output.contains(&self.authz),
                    "CLI output includes bearer; withheld"
                );
                panic!("CLI {step} exceeded bounded deadline: {output}");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        child.0.wait().unwrap();
        let output = std::fs::read_to_string(path).unwrap();
        assert!(
            !output.contains(&self.authn) && !output.contains(&self.authz),
            "CLI output unexpectedly includes fixture bearer; output withheld"
        );
        println!("CLI {step}: {output}");
        assert!(status.success(), "CLI {step} failed with {status}");
        output
    }
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
