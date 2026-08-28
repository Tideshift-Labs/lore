// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source-dark, descriptor-relative shared-spool observation.
//!
//! On Linux, every configured-root and artifact open rejects symlinks. Artifact opens are relative
//! to the retained root descriptor, remain beneath that root, and cannot cross a mount. The
//! verifier hashes the opened regular-file descriptor and reopens the derived path to reject an
//! identity change during observation. Its output is still non-authoritative: it grants no write,
//! publication, cleanup, ledger, quota, request, or provider authority.

use std::fmt;

use thiserror::Error;

use crate::spool::LedgerSpoolView;
use crate::spool::SpoolLayout;
use crate::spool::SpoolPaths;
use crate::spool::SpoolRecoveryDecision;
use crate::spool::VerifiedFileObservation;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SpoolVerificationError {
    #[error("shared spool verification is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("shared spool root is invalid")]
    InvalidRoot,
    #[error("shared spool root is unavailable")]
    RootUnavailable,
    #[error("shared spool root changed after verifier initialization")]
    RootChanged,
    #[error("derived spool path does not belong to the verifier root")]
    PathBindingMismatch,
    #[error("expected spool body size is invalid")]
    InvalidExpectedSize,
    #[error("shared spool observation is unavailable")]
    ObservationUnavailable,
    #[error("shared spool file size is invalid")]
    InvalidFileSize,
    #[error("shared spool file changed during observation")]
    FileChanged,
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs::File;
    use std::io::Read;
    use std::path::Component;
    use std::path::Path;
    use std::path::PathBuf;

    use rustix::fd::OwnedFd;
    use rustix::fs::FileType;
    use rustix::fs::Mode;
    use rustix::fs::OFlags;
    use rustix::fs::ResolveFlags;
    use rustix::fs::Stat;
    use rustix::io::Errno;

    use super::LedgerSpoolView;
    use super::SpoolLayout;
    use super::SpoolPaths;
    use super::SpoolRecoveryDecision;
    use super::SpoolVerificationError;
    use super::VerifiedFileObservation;

    const ROOT_RESOLVE: ResolveFlags = ResolveFlags::NO_MAGICLINKS
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::BENEATH);
    const ARTIFACT_RESOLVE: ResolveFlags = ROOT_RESOLVE.union(ResolveFlags::NO_XDEV);
    const ROOT_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW);
    const ARTIFACT_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK);

    pub struct LinuxSpoolVerifier {
        root_path: PathBuf,
        relative_root: PathBuf,
        filesystem_root_fd: OwnedFd,
        root_fd: OwnedFd,
        root_device: u64,
        root_inode: u64,
        root_binding_blake3: [u8; 32],
        maximum_file_bytes: u64,
    }

    impl LinuxSpoolVerifier {
        pub fn open(
            layout: &SpoolLayout,
            maximum_file_bytes: u64,
        ) -> Result<Self, SpoolVerificationError> {
            if maximum_file_bytes == 0 || maximum_file_bytes > i64::MAX as u64 {
                return Err(SpoolVerificationError::InvalidExpectedSize);
            }
            let root_path = layout.shared_spool_root();
            let relative_root = root_path
                .strip_prefix(Path::new("/"))
                .map_err(|_| SpoolVerificationError::InvalidRoot)?;
            if relative_root.as_os_str().is_empty()
                || relative_root
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(SpoolVerificationError::InvalidRoot);
            }
            let filesystem_root = rustix::fs::open("/", ROOT_FLAGS, Mode::empty())
                .map_err(|_| SpoolVerificationError::RootUnavailable)?;
            let root_fd = rustix::fs::openat2(
                &filesystem_root,
                relative_root,
                ROOT_FLAGS,
                Mode::empty(),
                ROOT_RESOLVE,
            )
            .map_err(|_| SpoolVerificationError::RootUnavailable)?;
            let root_stat =
                rustix::fs::fstat(&root_fd).map_err(|_| SpoolVerificationError::RootUnavailable)?;
            if !FileType::from_raw_mode(root_stat.st_mode).is_dir() {
                return Err(SpoolVerificationError::InvalidRoot);
            }
            let root_binding_blake3 = root_binding_blake3(root_stat.st_dev, root_stat.st_ino);
            Ok(Self {
                root_path: root_path.to_path_buf(),
                relative_root: relative_root.to_path_buf(),
                filesystem_root_fd: filesystem_root,
                root_fd,
                root_device: root_stat.st_dev,
                root_inode: root_stat.st_ino,
                root_binding_blake3,
                maximum_file_bytes,
            })
        }

        pub fn observe(
            &self,
            paths: &SpoolPaths,
            expected_size: u64,
        ) -> Result<VerifiedFileObservation, SpoolVerificationError> {
            self.assert_configured_root_stable()?;
            if expected_size > self.maximum_file_bytes {
                return Err(SpoolVerificationError::InvalidExpectedSize);
            }
            let part_path = self.relative_artifact_path(paths.part_path())?;
            let blob_path = self.relative_artifact_path(paths.final_path())?;
            let part = self.open_artifact(&part_path)?;
            let blob = self.open_artifact(&blob_path)?;
            let observation = match (part, blob) {
                (OpenedArtifact::Unsafe, _) | (_, OpenedArtifact::Unsafe) => Ok(
                    VerifiedFileObservation::unsafe_or_non_regular(paths, self.root_binding_blake3),
                ),
                (OpenedArtifact::Regular(_), OpenedArtifact::Regular(_)) => Ok(
                    VerifiedFileObservation::both(paths, self.root_binding_blake3),
                ),
                (OpenedArtifact::Absent, OpenedArtifact::Absent) => Ok(
                    VerifiedFileObservation::none(paths, self.root_binding_blake3),
                ),
                (OpenedArtifact::Regular(opened), OpenedArtifact::Absent) => {
                    let size = file_size(&opened.initial)?;
                    if size > expected_size || size > self.maximum_file_bytes {
                        return Err(SpoolVerificationError::InvalidFileSize);
                    }
                    let digest = if size == expected_size {
                        Some(self.hash_stable(opened, &part_path, size)?)
                    } else {
                        self.assert_stable(opened, &part_path)?;
                        None
                    };
                    Ok(VerifiedFileObservation::part(
                        paths,
                        self.root_binding_blake3,
                        size,
                        digest,
                    ))
                }
                (OpenedArtifact::Absent, OpenedArtifact::Regular(opened)) => {
                    let size = file_size(&opened.initial)?;
                    if size != expected_size || size > self.maximum_file_bytes {
                        return Err(SpoolVerificationError::InvalidFileSize);
                    }
                    let digest = self.hash_stable(opened, &blob_path, size)?;
                    Ok(VerifiedFileObservation::blob(
                        paths,
                        self.root_binding_blake3,
                        size,
                        digest,
                    ))
                }
            }?;
            self.assert_configured_root_stable()?;
            Ok(observation)
        }

        pub fn classify_recovery(
            &self,
            ledger: &LedgerSpoolView,
            observation: &VerifiedFileObservation,
            paths: &SpoolPaths,
        ) -> Result<SpoolRecoveryDecision, SpoolVerificationError> {
            self.assert_configured_root_stable()?;
            self.relative_artifact_path(paths.part_path())?;
            self.relative_artifact_path(paths.final_path())?;
            if observation.verifier_root_binding_blake3() != self.root_binding_blake3 {
                return Ok(SpoolRecoveryDecision::FailClosed(
                    crate::spool::SpoolRecoveryInconsistency::ObservationRootMismatch,
                ));
            }
            Ok(crate::spool::classify_spool_recovery(
                ledger,
                *observation,
                paths,
            ))
        }

        fn relative_artifact_path(
            &self,
            artifact_path: &Path,
        ) -> Result<PathBuf, SpoolVerificationError> {
            let relative = artifact_path
                .strip_prefix(&self.root_path)
                .map_err(|_| SpoolVerificationError::PathBindingMismatch)?;
            if relative.as_os_str().is_empty()
                || relative
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(SpoolVerificationError::PathBindingMismatch);
            }
            Ok(relative.to_path_buf())
        }

        fn open_artifact(
            &self,
            relative_path: &Path,
        ) -> Result<OpenedArtifact, SpoolVerificationError> {
            let fd = match rustix::fs::openat2(
                &self.root_fd,
                relative_path,
                ARTIFACT_FLAGS,
                Mode::empty(),
                ARTIFACT_RESOLVE,
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => return Ok(OpenedArtifact::Absent),
                Err(Errno::LOOP | Errno::XDEV | Errno::NOTDIR) => {
                    return Ok(OpenedArtifact::Unsafe);
                }
                Err(_) => return Err(SpoolVerificationError::ObservationUnavailable),
            };
            let initial = rustix::fs::fstat(&fd)
                .map_err(|_| SpoolVerificationError::ObservationUnavailable)?;
            if initial.st_dev != self.root_device
                || !FileType::from_raw_mode(initial.st_mode).is_file()
            {
                return Ok(OpenedArtifact::Unsafe);
            }
            Ok(OpenedArtifact::Regular(OpenedRegular {
                file: File::from(fd),
                initial,
            }))
        }

        fn assert_configured_root_stable(&self) -> Result<(), SpoolVerificationError> {
            let reopened = rustix::fs::openat2(
                &self.filesystem_root_fd,
                &self.relative_root,
                ROOT_FLAGS,
                Mode::empty(),
                ROOT_RESOLVE,
            )
            .map_err(|_| SpoolVerificationError::RootChanged)?;
            let current =
                rustix::fs::fstat(&reopened).map_err(|_| SpoolVerificationError::RootChanged)?;
            if current.st_dev != self.root_device || current.st_ino != self.root_inode {
                return Err(SpoolVerificationError::RootChanged);
            }
            Ok(())
        }

        fn hash_stable(
            &self,
            mut opened: OpenedRegular,
            relative_path: &Path,
            expected_size: u64,
        ) -> Result<[u8; 32], SpoolVerificationError> {
            let mut hasher = blake3::Hasher::new();
            let mut buffer = [0_u8; 64 * 1024];
            let mut observed_size = 0_u64;
            loop {
                let read = opened
                    .file
                    .read(&mut buffer)
                    .map_err(|_| SpoolVerificationError::ObservationUnavailable)?;
                if read == 0 {
                    break;
                }
                observed_size = observed_size
                    .checked_add(read as u64)
                    .ok_or(SpoolVerificationError::InvalidFileSize)?;
                if observed_size > expected_size || observed_size > self.maximum_file_bytes {
                    return Err(SpoolVerificationError::InvalidFileSize);
                }
                hasher.update(&buffer[..read]);
            }
            if observed_size != expected_size {
                return Err(SpoolVerificationError::FileChanged);
            }
            self.assert_stable(opened, relative_path)?;
            Ok(*hasher.finalize().as_bytes())
        }

        fn assert_stable(
            &self,
            opened: OpenedRegular,
            relative_path: &Path,
        ) -> Result<(), SpoolVerificationError> {
            let after_read = rustix::fs::fstat(&opened.file)
                .map_err(|_| SpoolVerificationError::ObservationUnavailable)?;
            let reopened = match self.open_artifact(relative_path)? {
                OpenedArtifact::Regular(reopened) => reopened,
                OpenedArtifact::Absent | OpenedArtifact::Unsafe => {
                    return Err(SpoolVerificationError::FileChanged);
                }
            };
            if !same_identity(&opened.initial, &after_read)
                || !same_identity(&opened.initial, &reopened.initial)
            {
                return Err(SpoolVerificationError::FileChanged);
            }
            Ok(())
        }
    }

    impl std::fmt::Debug for LinuxSpoolVerifier {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("LinuxSpoolVerifier")
                .field("root_path", &"[REDACTED]")
                .field("root_fd", &"[REDACTED]")
                .field("filesystem_root_fd", &"[REDACTED]")
                .field("root_device", &"[REDACTED]")
                .field("root_inode", &"[REDACTED]")
                .field("root_binding_blake3", &"[REDACTED]")
                .field("maximum_file_bytes", &self.maximum_file_bytes)
                .finish()
        }
    }

    enum OpenedArtifact {
        Absent,
        Unsafe,
        Regular(OpenedRegular),
    }

    struct OpenedRegular {
        file: File,
        initial: Stat,
    }

    fn file_size(stat: &Stat) -> Result<u64, SpoolVerificationError> {
        u64::try_from(stat.st_size).map_err(|_| SpoolVerificationError::InvalidFileSize)
    }

    fn same_identity(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev
            && left.st_ino == right.st_ino
            && left.st_mode == right.st_mode
            && left.st_size == right.st_size
            && left.st_mtime == right.st_mtime
            && left.st_mtime_nsec == right.st_mtime_nsec
            && left.st_ctime == right.st_ctime
            && left.st_ctime_nsec == right.st_ctime_nsec
    }

    fn root_binding_blake3(device: u64, inode: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"object-store-spool-verifier-root-v1\0");
        hasher.update(&device.to_be_bytes());
        hasher.update(&inode.to_be_bytes());
        *hasher.finalize().as_bytes()
    }

    pub use LinuxSpoolVerifier as ExportedLinuxSpoolVerifier;
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::LedgerSpoolView;
    use super::SpoolLayout;
    use super::SpoolPaths;
    use super::SpoolRecoveryDecision;
    use super::SpoolVerificationError;
    use super::VerifiedFileObservation;

    pub struct LinuxSpoolVerifier;

    impl LinuxSpoolVerifier {
        pub fn open(
            _layout: &SpoolLayout,
            _maximum_file_bytes: u64,
        ) -> Result<Self, SpoolVerificationError> {
            Err(SpoolVerificationError::UnsupportedPlatform)
        }

        pub fn observe(
            &self,
            _paths: &SpoolPaths,
            _expected_size: u64,
        ) -> Result<VerifiedFileObservation, SpoolVerificationError> {
            Err(SpoolVerificationError::UnsupportedPlatform)
        }

        pub fn classify_recovery(
            &self,
            _ledger: &LedgerSpoolView,
            _observation: &VerifiedFileObservation,
            _paths: &SpoolPaths,
        ) -> Result<SpoolRecoveryDecision, SpoolVerificationError> {
            Err(SpoolVerificationError::UnsupportedPlatform)
        }
    }

    impl std::fmt::Debug for LinuxSpoolVerifier {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.debug_struct("LinuxSpoolVerifier").finish()
        }
    }

    pub use LinuxSpoolVerifier as ExportedLinuxSpoolVerifier;
}

pub use platform::ExportedLinuxSpoolVerifier as LinuxSpoolVerifier;

impl fmt::Display for LinuxSpoolVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LinuxSpoolVerifier([REDACTED])")
    }
}
