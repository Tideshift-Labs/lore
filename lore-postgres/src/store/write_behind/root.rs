// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The confined staging root: derivation, resolution, and bounded reads.
//!
//! # Path confinement is derivation, not joining
//!
//! No database string is ever treated as a path here. A staged epoch is
//! identified by a typed `(hash: &[u8; 32], epoch: i64)` pair, and this module
//! *computes* the key and the path from it:
//!
//! ```text
//! key  = "<64 lowercase hex>.s<epoch>"
//! path = <root>/staged/<key[0..2]>/<key[2..4]>/<key>
//! ```
//!
//! `hex` emits only `[0-9a-f]` and `epoch` is a non-negative decimal `i64`, so
//! no component can contain a separator, a `..`, a NUL, a drive letter or a UNC
//! prefix. Traversal is not filtered out; it is unrepresentable, because there
//! is no caller-supplied string in the path to traverse with.
//!
//! The stored key is then required to be **byte-equal** to the derived key
//! ([`ConfinedRoot::resolve`]). That is strictly stronger than checking that a
//! joined path stays under the root, and it is necessary: the coordinator
//! persists whatever `object_key` the manifest carries without revalidating it
//! (`domain/fragments/coordinator.rs`'s `commit_staged` path, in contrast to
//! `begin_direct_write`, which does check its key against the hash).
//!
//! # The derived key is a twin, and the twin is pinned by a live test
//!
//! `staged_epoch_key` in `domain/fragments/coordinator.rs` is private to that
//! module, so [`derived_staged_key`] re-derives the same string rather than
//! calling it. The two must not drift. `staged_key_matches_the_coordinator` in
//! the live tier asserts that a real `begin_stage` intent's `object_key` equals
//! this function's output; a `pub(crate)` export from the coordinator would let
//! the compiler hold this instead, and is worth taking if that lane offers one.
//!
//! # Residual this module does NOT close
//!
//! `O_NOFOLLOW` covers the **final** component, and the recorded device covers a
//! move to another filesystem. Neither catches a same-device symlink planted at
//! an intermediate fan-out component. [`ConfinedRoot::ensure_parent`] uses
//! `create_dir`, which fails on an existing symlink, so a fan-out directory this
//! process created cannot be swapped for one; but a symlink planted *before*
//! first use, by something already able to write inside the root, is not
//! detected. Closing it needs an `openat`-from-root-dirfd walk, which needs raw
//! fd `unsafe` FFI this crate does not otherwise have — and an attacker who can
//! write inside the root already owns the staged bytes. The residual is
//! documented rather than silently accepted.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use super::WriteBehindError;
use super::admission::AdmissionSample;

/// Subdirectory holding finalized, readable staged files.
// Everything below that only the `cfg(unix)` platform module reads is dead on a
// platform that cannot stage. That is the point of the split, not an oversight,
// so the allow is conditional rather than blanket: on Unix these must stay live
// and a real dead-code warning must still be a warning.
#[cfg_attr(not(unix), expect(dead_code, reason = "staging is Unix-only"))]
pub(crate) const STAGED_DIR: &str = "staged";
/// Subdirectory holding temporary files that are never readable as fragments.
///
/// A sibling of `staged/`, not a child: a rename must stay within one
/// filesystem, and a half-written temp file must be unable to resolve through
/// the read path. Its name has no valid `<hash>.s<epoch>` shape and it is not
/// under `staged/`, so both hold.
#[cfg_attr(not(unix), expect(dead_code, reason = "staging is Unix-only"))]
pub(crate) const INCOMING_DIR: &str = "incoming";

/// A staged path this process derived and may act on.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedStagedPath {
    path: PathBuf,
    parent: PathBuf,
}

impl ResolvedStagedPath {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn parent(&self) -> &Path {
        &self.parent
    }
}

#[cfg_attr(not(unix), expect(dead_code, reason = "staging is Unix-only"))]
struct RootInner {
    canonical: PathBuf,
    staged: PathBuf,
    incoming: PathBuf,
    /// `st_dev` of the root at open time. Every later act revalidates against
    /// it, which is what stops a bind-mount or unmount from silently relocating
    /// the staged set, and also what keeps `rename` atomic.
    device: u64,
}

/// A proven staging root.
#[derive(Clone)]
pub(crate) struct ConfinedRoot {
    inner: Arc<RootInner>,
}

/// Derive the staged key for one epoch.
///
/// Twin of the coordinator's private `staged_epoch_key`; see this module's
/// header for how the two are held together.
///
/// # Errors
///
/// Returns [`WriteBehindError::HashWidth`] unless the hash is exactly 32 bytes
/// — it arrives as `Vec<u8>` from the domain layer, not `[u8; 32]`, so the width
/// is a runtime fact — and [`WriteBehindError::EpochNegative`] for a negative
/// epoch, which would put a `-` in a path component.
pub(crate) fn derived_staged_key(hash: &[u8], epoch: i64) -> Result<String, WriteBehindError> {
    if hash.len() != 32 {
        return Err(WriteBehindError::HashWidth);
    }
    if epoch < 0 {
        return Err(WriteBehindError::EpochNegative);
    }
    Ok(format!("{}.s{epoch}", hex::encode(hash)))
}

impl ConfinedRoot {
    pub(crate) fn incoming(&self) -> &Path {
        &self.inner.incoming
    }

    /// Resolve one staged epoch to a path this process may act on.
    ///
    /// Pure: no syscall, no I/O. The device revalidation that makes an `ENOENT`
    /// trustworthy belongs to the acting methods, not to resolution.
    ///
    /// # Errors
    ///
    /// Returns [`WriteBehindError::KeyMismatch`] when the stored key is not the
    /// derived key, plus the width and range errors from
    /// [`derived_staged_key`].
    pub(crate) fn resolve(
        &self,
        hash: &[u8],
        epoch: i64,
        stored_key: &str,
    ) -> Result<ResolvedStagedPath, WriteBehindError> {
        let derived = derived_staged_key(hash, epoch)?;
        if stored_key != derived {
            return Err(WriteBehindError::KeyMismatch);
        }
        // Indexing is safe without a bounds check only because `derived` is this
        // function's own output: 64 hex characters then `.s<digits>`, so it is
        // always at least 4 ASCII bytes. Slicing the stored key instead would
        // reintroduce exactly the caller-controlled path this design removes.
        let parent = self.inner.staged.join(&derived[0..2]).join(&derived[2..4]);
        let path = parent.join(&derived);
        Ok(ResolvedStagedPath { path, parent })
    }
}

#[cfg(unix)]
mod platform {
    use std::ffi::CString;
    use std::fs;
    use std::io::Read as _;
    use std::io::Write as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::path::Path;
    use std::sync::Arc;

    use bytes::Bytes;
    use lore_base::lore_spawn_blocking;
    use lore_base::types::FRAGMENT_SIZE_THRESHOLD;

    use super::AdmissionSample;
    use super::ConfinedRoot;
    use super::INCOMING_DIR;
    use super::ResolvedStagedPath;
    use super::RootInner;
    use super::STAGED_DIR;
    use super::WriteBehindError;

    impl ConfinedRoot {
        /// Prove the configured root, then record its device.
        ///
        /// Step 3 is a real durability probe, not an existence check: it writes,
        /// fsyncs, renames and fsyncs a directory through the same calls a real
        /// stage makes, so a mount that cannot fsync a directory fails at boot
        /// rather than at the first acknowledged PUT.
        pub(crate) fn open(configured: &Path) -> Result<Self, WriteBehindError> {
            let canonical =
                fs::canonicalize(configured).map_err(|_| WriteBehindError::RootUnresolvable)?;
            let metadata =
                fs::metadata(&canonical).map_err(|_| WriteBehindError::RootUnresolvable)?;
            if !metadata.is_dir() {
                return Err(WriteBehindError::RootNotADirectory);
            }
            let device = metadata.dev();
            let staged = canonical.join(STAGED_DIR);
            let incoming = canonical.join(INCOMING_DIR);
            for directory in [&staged, &incoming] {
                if let Err(error) = fs::create_dir(directory)
                    && error.kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(WriteBehindError::io("root directory create", &error));
                }
            }
            let root = Self {
                inner: Arc::new(RootInner {
                    canonical,
                    staged,
                    incoming,
                    device,
                }),
            };
            root.probe()?;
            Ok(root)
        }

        /// Exercise write, fsync, rename-within-filesystem and directory fsync.
        fn probe(&self) -> Result<(), WriteBehindError> {
            let token = uuid::Uuid::now_v7().simple().to_string();
            let temporary = self.inner.incoming.join(format!("probe-{token}.tmp"));
            let finalized = self.inner.staged.join(format!("probe-{token}"));
            let outcome = (|| -> Result<(), WriteBehindError> {
                let mut file = fs::File::create(&temporary)
                    .map_err(|error| WriteBehindError::io("probe create", &error))?;
                file.write_all(b"lore-write-behind-probe")
                    .map_err(|error| WriteBehindError::io("probe write", &error))?;
                file.sync_all()
                    .map_err(|error| WriteBehindError::io("probe fsync", &error))?;
                drop(file);
                fs::rename(&temporary, &finalized)
                    .map_err(|error| WriteBehindError::io("probe rename", &error))?;
                sync_directory(&self.inner.staged)?;
                fs::remove_file(&finalized)
                    .map_err(|error| WriteBehindError::io("probe unlink", &error))?;
                sync_directory(&self.inner.staged)
            })();
            // Leave nothing behind on either arm. A failed probe is a refusal to
            // start, and a refusal should not also litter the operator's mount.
            let _ = fs::remove_file(&temporary);
            let _ = fs::remove_file(&finalized);
            outcome.map_err(|error| match error {
                WriteBehindError::Io { .. } => WriteBehindError::RootProbeFailed,
                other => other,
            })
        }

        /// Confirm the root still sits on the filesystem recorded at open.
        ///
        /// This is what makes an `ENOENT` from [`Self::read_regular`] mean "this
        /// fragment is gone" rather than "the mount went away", which is the
        /// distinction that keeps a healthy fragment from being demoted to
        /// `Missing`.
        pub(crate) fn verify_device(&self) -> Result<(), WriteBehindError> {
            let metadata = fs::metadata(&self.inner.canonical)
                .map_err(|_| WriteBehindError::RootDeviceChanged)?;
            if metadata.dev() != self.inner.device {
                return Err(WriteBehindError::RootDeviceChanged);
            }
            Ok(())
        }

        /// Create the fan-out directories for one staged path and make them
        /// durable.
        ///
        /// **Ordering matters and is the reason this is a separate step.** The
        /// directory entries must be durable *before* the rename that publishes
        /// the file into them, or a crash can leave the leaf entry
        /// non-durable after `commit_staged` has already made the row
        /// authoritative — a `Staged` row with no readable file, which
        /// ADR-00027 classifies as corruption.
        ///
        /// `create_dir` (not `create_dir_all`) is deliberate: it fails on an
        /// existing symlink, so a fan-out component this process created cannot
        /// later be swapped for one. See the module header for the residual it
        /// does not cover.
        pub(crate) fn ensure_parent(
            &self,
            resolved: &ResolvedStagedPath,
        ) -> Result<(), WriteBehindError> {
            let parent = resolved.parent();
            let Some(grandparent) = parent.parent() else {
                return Err(WriteBehindError::RootUnresolvable);
            };
            let mut created_grandparent = false;
            match fs::create_dir(grandparent) {
                Ok(()) => created_grandparent = true,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(WriteBehindError::io("fanout create", &error)),
            }
            if created_grandparent {
                sync_directory(&self.inner.staged)?;
            }
            let mut created_parent = false;
            match fs::create_dir(parent) {
                Ok(()) => created_parent = true,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(WriteBehindError::io("fanout create", &error)),
            }
            if created_parent {
                sync_directory(grandparent)?;
            }
            Ok(())
        }

        /// Read one staged file, bounded, refusing anything that is not a
        /// regular file on the recorded device.
        ///
        /// `Ok(None)` is a real `ENOENT` and nothing else.
        pub(crate) async fn read_regular(
            &self,
            resolved: &ResolvedStagedPath,
        ) -> Result<Option<Bytes>, WriteBehindError> {
            self.verify_device()?;
            let path = resolved.path().to_path_buf();
            let device = self.inner.device;
            join(lore_spawn_blocking!(move || read_regular_blocking(
                &path, device
            )))
            .await
        }

        /// Remove one exact staged file and make the removal durable.
        ///
        /// `Ok(())` for an already-absent file: cleanup is idempotent, and a
        /// retried purge after a crash must not fail.
        pub(crate) async fn remove_regular(
            &self,
            resolved: &ResolvedStagedPath,
        ) -> Result<(), WriteBehindError> {
            self.verify_device()?;
            let path = resolved.path().to_path_buf();
            let parent = resolved.parent().to_path_buf();
            join(lore_spawn_blocking!(move || {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                    Err(error) => return Err(WriteBehindError::io("staged unlink", &error)),
                }
                sync_directory(&parent)
            }))
            .await
        }

        /// Sample free space and root reachability for the admission snapshot.
        pub(crate) fn sample(&self) -> AdmissionSample {
            if self.verify_device().is_err() {
                return AdmissionSample::RootUnavailable;
            }
            match free_bytes(&self.inner.canonical) {
                Ok(free) => AdmissionSample::Reachable { free_bytes: free },
                Err(_) => AdmissionSample::RootUnavailable,
            }
        }
    }

    fn read_regular_blocking(path: &Path, device: u64) -> Result<Option<Bytes>, WriteBehindError> {
        // O_NOFOLLOW covers the final component: a symlink planted where the
        // staged file belongs is ELOOP here rather than a read of whatever it
        // names.
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(WriteBehindError::io("staged open", &error)),
        };
        let metadata = file
            .metadata()
            .map_err(|error| WriteBehindError::io("staged stat", &error))?;
        if !metadata.is_file() {
            return Err(WriteBehindError::NotARegularFile);
        }
        if metadata.dev() != device {
            return Err(WriteBehindError::RootDeviceChanged);
        }
        // Refuse before allocating. `tokio::fs::read`, which this replaced,
        // sizes its buffer from the file length and would happily allocate an
        // oversized one first.
        let length = metadata.len();
        if length > FRAGMENT_SIZE_THRESHOLD as u64 {
            return Err(WriteBehindError::PayloadOversized);
        }
        let mut buffer = Vec::with_capacity(length as usize);
        let mut handle = file.take(FRAGMENT_SIZE_THRESHOLD as u64 + 1);
        handle
            .read_to_end(&mut buffer)
            .map_err(|error| WriteBehindError::io("staged read", &error))?;
        if buffer.len() > FRAGMENT_SIZE_THRESHOLD {
            return Err(WriteBehindError::PayloadOversized);
        }
        Ok(Some(Bytes::from(buffer)))
    }

    /// fsync one directory so its entries survive a crash.
    pub(crate) fn sync_directory(directory: &Path) -> Result<(), WriteBehindError> {
        let handle = fs::File::open(directory)
            .map_err(|error| WriteBehindError::io("directory open", &error))?;
        handle
            .sync_all()
            .map_err(|error| WriteBehindError::io("directory fsync", &error))
    }

    fn free_bytes(path: &Path) -> Result<u64, WriteBehindError> {
        let raw = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| WriteBehindError::RootUnresolvable)?;
        // SAFETY: `statvfs` writes into a fully owned, correctly sized value and
        // reads `raw`, a NUL-terminated C string that outlives the call. The
        // return code is checked before the value is read.
        let stats = unsafe {
            let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            if libc::statvfs(raw.as_ptr(), stats.as_mut_ptr()) != 0 {
                return Err(WriteBehindError::RootUnresolvable);
            }
            stats.assume_init()
        };
        Ok(u64::from(stats.f_bavail).saturating_mul(u64::from(stats.f_frsize)))
    }

    /// Unwrap a blocking join, mapping a panicked or cancelled task to an I/O
    /// failure rather than propagating a panic into the store.
    async fn join<T>(
        handle: tokio::task::JoinHandle<Result<T, WriteBehindError>>,
    ) -> Result<T, WriteBehindError> {
        match handle.await {
            Ok(result) => result,
            Err(_) => Err(WriteBehindError::Io {
                operation: "blocking join",
                kind: std::io::ErrorKind::Interrupted,
            }),
        }
    }
}

#[cfg(not(unix))]
mod platform {
    use std::path::Path;

    use bytes::Bytes;

    use super::AdmissionSample;
    use super::ConfinedRoot;
    use super::ResolvedStagedPath;
    use super::WriteBehindError;

    // Staging is Unix-only (owner ruling, 2026-09-16): directory fsync and
    // rename-over semantics differ enough that a Windows implementation would be
    // a weaker durability guarantee wearing the same name.
    //
    // The module still COMPILES here on purpose. Cfg-ing the whole staging
    // module out would leave the staged read arm in `immutable_store.rs` on its
    // old `tokio::fs::read`, which reintroduces exactly the fail-open that
    // demotes a healthy fragment to `Missing`. A platform that cannot stage must
    // still be unable to answer "absent" wrongly.
    impl ConfinedRoot {
        pub(crate) fn open(_configured: &Path) -> Result<Self, WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) fn verify_device(&self) -> Result<(), WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) fn ensure_parent(
            &self,
            _resolved: &ResolvedStagedPath,
        ) -> Result<(), WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) async fn read_regular(
            &self,
            _resolved: &ResolvedStagedPath,
        ) -> Result<Option<Bytes>, WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) async fn remove_regular(
            &self,
            _resolved: &ResolvedStagedPath,
        ) -> Result<(), WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) fn sample(&self) -> AdmissionSample {
            AdmissionSample::RootUnavailable
        }
    }

    pub(crate) fn sync_directory(_directory: &Path) -> Result<(), WriteBehindError> {
        Err(WriteBehindError::UnsupportedPlatform)
    }
}

pub(crate) use platform::sync_directory;

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: [u8; 32] = [0xAB; 32];

    #[test]
    fn derived_key_is_lowercase_hex_with_the_epoch_suffix() {
        let key = derived_staged_key(&HASH, 7).expect("derive");
        assert_eq!(key, format!("{}.s7", "ab".repeat(32)));
    }

    #[test]
    fn derived_key_refuses_a_hash_that_is_not_thirty_two_bytes() {
        assert_eq!(
            derived_staged_key(&[0u8; 31], 1),
            Err(WriteBehindError::HashWidth)
        );
        assert_eq!(
            derived_staged_key(&[0u8; 33], 1),
            Err(WriteBehindError::HashWidth)
        );
        assert_eq!(derived_staged_key(&[], 1), Err(WriteBehindError::HashWidth));
    }

    #[test]
    fn derived_key_refuses_a_negative_epoch() {
        assert_eq!(
            derived_staged_key(&HASH, -1),
            Err(WriteBehindError::EpochNegative)
        );
    }
}
