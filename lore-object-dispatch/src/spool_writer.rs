// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Descriptor-relative durable spool body writer.
//!
//! WP-122 L5. Before this module nothing in the tree wrote into the shared spool
//! root: [`crate::spool`] only derives paths and [`crate::spool_verifier`] only
//! reads them. A drain worker has to put the body there before
//! `put_spool_ready` can assert it is durable, and the assertion is only true if
//! the placement was durable in the first place.
//!
//! # The ordering is the contract
//!
//! Copied, deliberately, from `lore-postgres`'s
//! `store/write_behind/finalize.rs` rather than invented here. In exactly this
//! order:
//!
//! 1. create each directory level below the root, and fsync **its parent**
//!    before descending;
//! 2. write the body to the derived `.part` file;
//! 3. fsync the `.part` file — `sync_all`, because the rename publishes metadata
//!    as well as contents;
//! 4. rename it onto the derived `.blob` path;
//! 5. fsync the leaf directory that now holds the entry.
//!
//! Step 1 precedes step 4 and that is not cosmetic. Directory entries fsynced
//! only after the rename can be lost by a crash, leaving a reserved spool object
//! whose body cannot be found — and `put_spool_ready` would then record as
//! durable a handle that resolves to nothing. `AlreadyExists` from `mkdirat` is
//! not durability evidence: a peer may have created the directory without
//! syncing this root, so every writer establishes its own barrier.
//!
//! # What a crash leaves at each point
//!
//! - before step 4: a `.part` file. `SpoolRecoveryDecision` already classifies
//!   that state, and this module never publishes a handle for it.
//! - between step 4 and the caller's `put_spool_ready`: a complete, valid
//!   `.blob` with no ready row. That is the spool's own orphan class, and it is
//!   **not** this module's to reclaim — the same rule `write_behind/cleanup.rs`
//!   follows, for the same reason: a body with no row is indistinguishable from
//!   one whose ready call is in flight.
//!
//! # Confinement is stronger here than under the staging root, on purpose
//!
//! `ConfinedRoot` resolves absolute paths and covers only the final component
//! with `O_NOFOLLOW`, documenting an intermediate-symlink residual it does not
//! close. This module writes into the root that [`crate::spool_verifier`]
//! reads under `openat2` with `RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS |
//! NO_XDEV`, so it uses the same resolution. A writer weaker than the reader
//! could place bytes the reader is then obliged to refuse, which is a failure
//! mode with no useful diagnosis.
//!
//! # Authority this module does NOT grant
//!
//! It writes bytes and reports what it wrote. It grants no reservation, ledger,
//! quota, publication or cleanup authority, and its receipt is the **writer's
//! own observation** — the value `mark_spool_ready` documents as "as the writer
//! observed it". It is not an independent anchor and must not be used as one.

use std::fmt;

use thiserror::Error;

use crate::spool::SpoolLayout;
use crate::spool::SpoolObjectKey;

/// Largest body this writer accepts, matching the provider seam's ingress cap.
///
/// A drain body is one fragment, and a fragment is bounded at 256 KiB, so a
/// larger body is a defect rather than a large object. The bound is restated
/// here rather than imported so this crate keeps no dependency on the seam.
pub const MAX_SPOOL_BODY_BYTES: u64 = 256 * 1024;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SpoolWriteError {
    #[error("shared spool writing is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("shared spool root is invalid")]
    InvalidRoot,
    #[error("shared spool root is unavailable")]
    RootUnavailable,
    #[error("shared spool root changed after writer initialization")]
    RootChanged,
    #[error("shared spool body writer accepts only PUT spool objects")]
    InvalidSpoolKind,
    #[error("shared spool key is invalid")]
    InvalidSpoolKey,
    #[error("derived spool path does not belong to the writer root")]
    PathBindingMismatch,
    #[error("shared spool body size is invalid")]
    InvalidBodySize,
    #[error("shared spool part file already exists")]
    PartAlreadyPresent,
    #[error("shared spool body is already durable at its final path")]
    BodyAlreadyPresent,
    #[error("shared spool path resolves to an unsafe or non-regular entry")]
    UnsafeOrNonRegular,
    #[error("shared spool write failed at {operation}")]
    Io { operation: &'static str },
}

/// What one durable spool placement produced.
///
/// The handle is [`crate::spool::SpoolPaths::opaque_handle`] for the same key,
/// so it satisfies `bind_durable_put_body_from_ready`'s derived-handle equality
/// by construction rather than by a caller remembering to pass the right string.
#[derive(Clone, PartialEq, Eq)]
pub struct SpoolWriteReceipt {
    opaque_handle: String,
    size: u64,
    blake3: [u8; 32],
}

impl SpoolWriteReceipt {
    pub fn opaque_handle(&self) -> &str {
        &self.opaque_handle
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn blake3(&self) -> &[u8; 32] {
        &self.blake3
    }
}

impl fmt::Debug for SpoolWriteReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpoolWriteReceipt")
            .field("opaque_handle", &"[REDACTED]")
            .field("size", &self.size)
            .field("blake3", &"[REDACTED]")
            .finish()
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs::File;
    use std::io::Write as _;
    use std::path::Component;
    use std::path::Path;
    use std::path::PathBuf;

    use rustix::fd::OwnedFd;
    use rustix::fs::AtFlags;
    use rustix::fs::FileType;
    use rustix::fs::Mode;
    use rustix::fs::OFlags;
    use rustix::fs::ResolveFlags;
    use rustix::io::Errno;

    use super::MAX_SPOOL_BODY_BYTES;
    use super::SpoolLayout;
    use super::SpoolObjectKey;
    use super::SpoolWriteError;
    use super::SpoolWriteReceipt;
    use crate::spool::SpoolObjectKind;

    const ROOT_RESOLVE: ResolveFlags = ResolveFlags::NO_MAGICLINKS
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::BENEATH);
    const ARTIFACT_RESOLVE: ResolveFlags = ROOT_RESOLVE.union(ResolveFlags::NO_XDEV);
    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW);
    const PART_FLAGS: OFlags = OFlags::WRONLY
        .union(OFlags::CREATE)
        .union(OFlags::EXCL)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW);
    /// Owner-only. A spool body is server-private and no peer process reads it
    /// through the filesystem.
    const DIRECTORY_MODE: Mode = Mode::RWXU;
    const FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

    pub struct LinuxSpoolWriter {
        root_path: PathBuf,
        relative_root: PathBuf,
        filesystem_root_fd: OwnedFd,
        root_fd: OwnedFd,
        root_device: u64,
        root_inode: u64,
        maximum_body_bytes: u64,
    }

    impl LinuxSpoolWriter {
        /// Open and pin the configured spool root.
        ///
        /// Mirrors `LinuxSpoolVerifier::open`: the same `openat2` resolution, the
        /// same retained filesystem-root descriptor, and the same recorded
        /// `(st_dev, st_ino)` that later calls revalidate against. It does not
        /// create the root — a root the operator has not provisioned is a
        /// configuration refusal, not something a writer invents.
        ///
        /// # Errors
        ///
        /// [`SpoolWriteError::InvalidBodySize`] for a zero or out-of-range
        /// bound, [`SpoolWriteError::InvalidRoot`] for a root that is not an
        /// absolute path of normal components, and
        /// [`SpoolWriteError::RootUnavailable`] when it cannot be opened.
        ///
        /// **The `is_dir` check below is defence in depth, not a reachable
        /// arm**, and the pins measured that rather than assuming it. `O_DIRECTORY`
        /// makes the kernel fail the `openat2` itself — `ENOENT` for an absent
        /// root, `ENOTDIR` for a regular file — so both arrive as
        /// `RootUnavailable` and this check never sees a non-directory. It is
        /// kept because `LinuxSpoolVerifier::open` keeps the identical one, and
        /// a reader comparing the two should not have to work out why they
        /// differ.
        pub fn open(
            layout: &SpoolLayout,
            maximum_body_bytes: u64,
        ) -> Result<Self, SpoolWriteError> {
            if maximum_body_bytes == 0 || maximum_body_bytes > MAX_SPOOL_BODY_BYTES {
                return Err(SpoolWriteError::InvalidBodySize);
            }
            let root_path = layout.shared_spool_root();
            let relative_root = root_path
                .strip_prefix(Path::new("/"))
                .map_err(|_| SpoolWriteError::InvalidRoot)?;
            if relative_root.as_os_str().is_empty()
                || relative_root
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(SpoolWriteError::InvalidRoot);
            }
            let filesystem_root = rustix::fs::open("/", DIRECTORY_FLAGS, Mode::empty())
                .map_err(|_| SpoolWriteError::RootUnavailable)?;
            let root_fd = rustix::fs::openat2(
                &filesystem_root,
                relative_root,
                DIRECTORY_FLAGS,
                Mode::empty(),
                ROOT_RESOLVE,
            )
            .map_err(|_| SpoolWriteError::RootUnavailable)?;
            let root_stat =
                rustix::fs::fstat(&root_fd).map_err(|_| SpoolWriteError::RootUnavailable)?;
            if !FileType::from_raw_mode(root_stat.st_mode).is_dir() {
                return Err(SpoolWriteError::InvalidRoot);
            }
            Ok(Self {
                root_path: root_path.to_path_buf(),
                relative_root: relative_root.to_path_buf(),
                filesystem_root_fd: filesystem_root,
                root_fd,
                root_device: root_stat.st_dev,
                root_inode: root_stat.st_ino,
                maximum_body_bytes,
            })
        }

        /// Durably place one PUT body and report what was written.
        ///
        /// The returned handle equals
        /// `layout.derive_paths(key)?.opaque_handle()`, which is the equality
        /// `bind_durable_put_body_from_ready` requires.
        ///
        /// # Errors
        ///
        /// Refuses before touching the filesystem for a non-PUT kind, an empty
        /// or oversized body, and an invalid key. Refuses
        /// [`SpoolWriteError::BodyAlreadyPresent`] rather than overwriting:
        /// `(logical_request_id, attempt_id)` names one attempt's body, an
        /// attempt identity is used once, and a second write under the same name
        /// would replace bytes another call may already have reported ready.
        pub fn write_put_body(
            &self,
            layout: &SpoolLayout,
            key: &SpoolObjectKey,
            body: &[u8],
        ) -> Result<SpoolWriteReceipt, SpoolWriteError> {
            if key.kind != SpoolObjectKind::Put {
                return Err(SpoolWriteError::InvalidSpoolKind);
            }
            let size = u64::try_from(body.len()).map_err(|_| SpoolWriteError::InvalidBodySize)?;
            if size == 0 || size > self.maximum_body_bytes {
                return Err(SpoolWriteError::InvalidBodySize);
            }
            let paths = layout
                .derive_paths(key)
                .map_err(|_| SpoolWriteError::InvalidSpoolKey)?;
            let blob_relative = self.relative_artifact_path(paths.final_path())?;
            let part_relative = self.relative_artifact_path(paths.part_path())?;

            self.assert_configured_root_stable()?;

            // Step 1. Every level below the root, each one made durable in its
            // parent before the walk descends into it.
            let Some(directory_relative) = blob_relative.parent() else {
                return Err(SpoolWriteError::PathBindingMismatch);
            };
            let directory_fd = self.ensure_directory_chain(directory_relative)?;

            let outcome = self.place_body(&part_relative, &blob_relative, &directory_fd, body);
            if outcome.is_err() {
                // Best effort, and exactly `finalize_blocking`'s reasoning: the
                // rename either happened or it did not. If it did this removes
                // nothing; if it did not this removes the part file that would
                // otherwise wait for recovery.
                let _ = rustix::fs::unlinkat(&self.root_fd, &part_relative, AtFlags::empty());
            }
            outcome?;

            self.assert_configured_root_stable()?;
            Ok(SpoolWriteReceipt {
                opaque_handle: paths.opaque_handle().to_string(),
                size,
                blake3: *blake3::hash(body).as_bytes(),
            })
        }

        /// Steps 2 through 5.
        fn place_body(
            &self,
            part_relative: &Path,
            blob_relative: &Path,
            directory_fd: &OwnedFd,
            body: &[u8],
        ) -> Result<(), SpoolWriteError> {
            // Refuse an existing final body before creating anything. This is
            // the check that makes `O_EXCL` on the part file a diagnosis rather
            // than the only guard: a crash between rename and the ready call
            // leaves a `.blob` and no `.part`, and silently rewriting it is the
            // one outcome that could change bytes another party already trusts.
            match rustix::fs::openat2(
                &self.root_fd,
                blob_relative,
                DIRECTORY_FLAGS.difference(OFlags::DIRECTORY),
                Mode::empty(),
                ARTIFACT_RESOLVE,
            ) {
                Ok(_) => return Err(SpoolWriteError::BodyAlreadyPresent),
                Err(Errno::NOENT) => {}
                Err(Errno::LOOP | Errno::XDEV | Errno::NOTDIR) => {
                    return Err(SpoolWriteError::UnsafeOrNonRegular);
                }
                Err(_) => {
                    return Err(SpoolWriteError::Io {
                        operation: "blob probe",
                    });
                }
            }

            // Step 2. `O_EXCL`: an attempt identity is used once, so an existing
            // part file is a concurrent or abandoned writer, never something to
            // truncate.
            let part_fd = match rustix::fs::openat2(
                &self.root_fd,
                part_relative,
                PART_FLAGS,
                FILE_MODE,
                ARTIFACT_RESOLVE,
            ) {
                Ok(fd) => fd,
                Err(Errno::EXIST) => return Err(SpoolWriteError::PartAlreadyPresent),
                Err(Errno::LOOP | Errno::XDEV | Errno::NOTDIR) => {
                    return Err(SpoolWriteError::UnsafeOrNonRegular);
                }
                Err(_) => {
                    return Err(SpoolWriteError::Io {
                        operation: "part create",
                    });
                }
            };
            let mut part = File::from(part_fd);
            part.write_all(body).map_err(|_| SpoolWriteError::Io {
                operation: "part write",
            })?;
            // Step 3. Contents and metadata, because the rename publishes both.
            part.sync_all().map_err(|_| SpoolWriteError::Io {
                operation: "part fsync",
            })?;
            drop(part);

            // Step 4. Both sides are relative to the pinned root descriptor, so
            // the rename cannot cross out of it and is atomic within the one
            // filesystem `NO_XDEV` has already held every open to.
            rustix::fs::renameat(&self.root_fd, part_relative, &self.root_fd, blob_relative)
                .map_err(|_| SpoolWriteError::Io {
                    operation: "part rename",
                })?;

            // Step 5.
            rustix::fs::fsync(directory_fd).map_err(|_| SpoolWriteError::Io {
                operation: "leaf directory fsync",
            })
        }

        /// Create every level of `relative` below the root, fsyncing each
        /// parent before descending, and return the leaf directory descriptor.
        fn ensure_directory_chain(&self, relative: &Path) -> Result<OwnedFd, SpoolWriteError> {
            let mut parent = self.root_fd.try_clone().map_err(|_| SpoolWriteError::Io {
                operation: "root descriptor clone",
            })?;
            for component in relative.components() {
                let Component::Normal(name) = component else {
                    return Err(SpoolWriteError::PathBindingMismatch);
                };
                match rustix::fs::mkdirat(&parent, name, DIRECTORY_MODE) {
                    Ok(()) => {}
                    // Not durability evidence. A peer may have created this
                    // entry without syncing, which is why the fsync below is
                    // unconditional rather than inside the `Ok` arm.
                    Err(Errno::EXIST) => {}
                    Err(_) => {
                        return Err(SpoolWriteError::Io {
                            operation: "fanout create",
                        });
                    }
                }
                rustix::fs::fsync(&parent).map_err(|_| SpoolWriteError::Io {
                    operation: "fanout parent fsync",
                })?;
                let child = match rustix::fs::openat2(
                    &parent,
                    name,
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                    ARTIFACT_RESOLVE,
                ) {
                    Ok(fd) => fd,
                    Err(Errno::LOOP | Errno::XDEV | Errno::NOTDIR) => {
                        return Err(SpoolWriteError::UnsafeOrNonRegular);
                    }
                    Err(_) => {
                        return Err(SpoolWriteError::Io {
                            operation: "fanout open",
                        });
                    }
                };
                let stat = rustix::fs::fstat(&child).map_err(|_| SpoolWriteError::Io {
                    operation: "fanout stat",
                })?;
                if stat.st_dev != self.root_device {
                    return Err(SpoolWriteError::UnsafeOrNonRegular);
                }
                parent = child;
            }
            Ok(parent)
        }

        fn relative_artifact_path(&self, artifact_path: &Path) -> Result<PathBuf, SpoolWriteError> {
            let relative = artifact_path
                .strip_prefix(&self.root_path)
                .map_err(|_| SpoolWriteError::PathBindingMismatch)?;
            if relative.as_os_str().is_empty()
                || relative
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(SpoolWriteError::PathBindingMismatch);
            }
            Ok(relative.to_path_buf())
        }

        fn assert_configured_root_stable(&self) -> Result<(), SpoolWriteError> {
            let reopened = rustix::fs::openat2(
                &self.filesystem_root_fd,
                &self.relative_root,
                DIRECTORY_FLAGS,
                Mode::empty(),
                ROOT_RESOLVE,
            )
            .map_err(|_| SpoolWriteError::RootChanged)?;
            let current = rustix::fs::fstat(&reopened).map_err(|_| SpoolWriteError::RootChanged)?;
            if current.st_dev != self.root_device || current.st_ino != self.root_inode {
                return Err(SpoolWriteError::RootChanged);
            }
            Ok(())
        }
    }

    impl std::fmt::Debug for LinuxSpoolWriter {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("LinuxSpoolWriter")
                .field("root_path", &"[REDACTED]")
                .field("root_fd", &"[REDACTED]")
                .field("filesystem_root_fd", &"[REDACTED]")
                .field("root_device", &"[REDACTED]")
                .field("root_inode", &"[REDACTED]")
                .field("maximum_body_bytes", &self.maximum_body_bytes)
                .finish()
        }
    }

    pub use LinuxSpoolWriter as ExportedLinuxSpoolWriter;
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::SpoolLayout;
    use super::SpoolObjectKey;
    use super::SpoolWriteError;
    use super::SpoolWriteReceipt;

    // Durable placement needs `renameat` and directory fsync semantics this
    // module can only assert on Linux, and the reader it feeds
    // (`LinuxSpoolVerifier`) is Linux-only for `openat2`. A weaker writer
    // wearing the same name is exactly what D13 refused for the staging root.
    pub struct LinuxSpoolWriter;

    impl LinuxSpoolWriter {
        pub fn open(
            _layout: &SpoolLayout,
            _maximum_body_bytes: u64,
        ) -> Result<Self, SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }

        pub fn write_put_body(
            &self,
            _layout: &SpoolLayout,
            _key: &SpoolObjectKey,
            _body: &[u8],
        ) -> Result<SpoolWriteReceipt, SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }
    }

    impl std::fmt::Debug for LinuxSpoolWriter {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.debug_struct("LinuxSpoolWriter").finish()
        }
    }

    pub use LinuxSpoolWriter as ExportedLinuxSpoolWriter;
}

pub use platform::ExportedLinuxSpoolWriter as LinuxSpoolWriter;
