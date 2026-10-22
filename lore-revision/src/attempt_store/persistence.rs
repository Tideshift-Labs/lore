// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Versioned journal persistence. All child operations hold the root's `FSLock`.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Write;

use super::*;

pub(crate) const BOOTSTRAP_FILE: &str = ".lore-workflow.bootstrap";
pub(crate) const BOOTSTRAP_LOCK_FILE: &str = ".lore-workflow.bootstrap.lock";
const DIRECTORY_TEMP_PREFIX: &str = ".lore-workflow.directory.";

#[cfg(feature = "test-util")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[lore_macro::test_pub]
pub(super) enum PublicationPoint {
    AfterWrite,
    AfterSync,
    BeforeRename,
    AfterRenameBeforeDirectorySync,
    BeforeDirectorySync,
    AfterDirectorySync,
    AfterRename,
}

#[cfg(feature = "test-util")]
type PublicationCallback =
    Arc<dyn Fn(PublicationPoint, &Path, &Path) -> Result<(), ProtocolError> + Send + Sync>;

#[cfg(feature = "test-util")]
fn publication_probes() -> &'static std::sync::Mutex<HashMap<PathBuf, PublicationCallback>> {
    static PROBES: std::sync::OnceLock<std::sync::Mutex<HashMap<PathBuf, PublicationCallback>>> =
        std::sync::OnceLock::new();
    PROBES.get_or_init(Default::default)
}

#[cfg(feature = "test-util")]
#[lore_macro::test_pub]
pub(super) struct PublicationProbe {
    root: PathBuf,
}

#[cfg(feature = "test-util")]
impl Drop for PublicationProbe {
    fn drop(&mut self) {
        if let Ok(mut probes) = publication_probes().lock() {
            probes.remove(&self.root);
        }
    }
}

#[cfg(feature = "test-util")]
#[lore_macro::test_pub]
pub(super) fn install_publication_probe(
    root: PathBuf,
    callback: impl Fn(PublicationPoint, &Path, &Path) -> Result<(), ProtocolError>
    + Send
    + Sync
    + 'static,
) -> PublicationProbe {
    let mut probes = publication_probes()
        .lock()
        .expect("publication test registry");
    assert!(
        !probes.contains_key(&root),
        "publication fixture roots must be unique"
    );
    probes.insert(root.clone(), Arc::new(callback));
    PublicationProbe { root }
}

#[cfg(feature = "test-util")]
fn publication_point(
    point: PublicationPoint,
    source: &Path,
    destination: &Path,
) -> Result<(), ProtocolError> {
    let callbacks = publication_probes()
        .lock()
        .expect("publication test registry")
        .iter()
        .filter(|(root, _)| destination.starts_with(root))
        .map(|(_, callback)| callback.clone())
        .collect::<Vec<_>>();
    for callback in callbacks {
        callback(point, source, destination)?;
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct StoredChild {
    version: u8,
    pub(super) attempt: StoredAttempt,
    pub(super) managed: Option<StoredManagedIntent>,
}

/// Single-use lookup retained while its journal lock is held. Callers must not write
/// another child between loading this value and passing it to `write_child`.
pub(super) struct LoadedChild<'guard> {
    _guard: &'guard FSLock,
    id: String,
    pub(super) child: Option<StoredChild>,
    path: Option<PathBuf>,
}

impl StoredChild {
    pub(super) fn new(attempt: StoredAttempt, managed: Option<StoredManagedIntent>) -> Self {
        Self {
            version: ATTEMPT_STORE_VERSION,
            attempt,
            managed,
        }
    }
}

pub(crate) fn is_directory_temporary(name: &str) -> bool {
    name.strip_prefix(DIRECTORY_TEMP_PREFIX)
        .and_then(|name| name.strip_suffix(TEMP_SUFFIX))
        .is_some_and(|id| Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id))
}

fn io_error(action: &str, path: &Path, error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::internal(format!(
        "Failed to {action} journal path {}: {error}",
        path.display()
    ))
}

/// Missing containers are published under a lock in their existing parent. Taking the lock
/// even when the destination exists waits for a concurrent publisher's durability barrier.
pub(crate) async fn ensure_directory(path: &Path) -> Result<(), ProtocolError> {
    let absolute = std::path::absolute(path).map_err(|error| io_error("resolve", path, error))?;
    let Some(parent) = absolute.parent() else {
        return Err(ProtocolError::internal("journal directory has no parent"));
    };
    if !parent.is_dir() {
        Box::pin(ensure_directory(parent)).await?;
    }
    // A prior publisher can leave a visible ancestor and then fail its directory sync.
    // Repair journal-created ancestors before using that visibility as authority. Existing
    // bootstrap sidecars identify their parents without creating files in system ancestors.
    #[cfg(feature = "test-util")]
    let repair = phase_diagnostics::start(
        Some(&absolute),
        if cfg!(windows) {
            "ancestor_repair_windows_test_only"
        } else {
            "ancestor_repair_unix"
        },
    );
    #[cfg(any(not(windows), feature = "test-util"))]
    for ancestor in parent.parent().into_iter().flat_map(Path::ancestors) {
        let bootstrap = ancestor.join(BOOTSTRAP_LOCK_FILE);
        match std::fs::metadata(&bootstrap) {
            Ok(_) => {
                let _repair = FSLock::acquire_file_lock(ancestor.join(BOOTSTRAP_FILE), false)
                    .await
                    .map_err(|error| io_error("lock ancestor bootstrap", ancestor, error))?;
                sync_directory(Some(ancestor))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(io_error("inspect ancestor bootstrap", &bootstrap, error)),
        }
    }
    #[cfg(feature = "test-util")]
    drop(repair);
    #[cfg(feature = "test-util")]
    let wait = phase_diagnostics::start(Some(&absolute), "bootstrap_fslock_wait");
    let _bootstrap = FSLock::acquire_file_lock(parent.join(BOOTSTRAP_FILE), false)
        .await
        .map_err(|error| io_error("lock bootstrap for", &absolute, error))?;
    #[cfg(feature = "test-util")]
    drop(wait);
    match std::fs::metadata(&absolute) {
        Ok(metadata) if metadata.is_dir() => sync_directory(Some(parent)),
        Ok(_) => Err(ProtocolError::internal(
            "journal directory is not a directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => publish_directory(&absolute),
        Err(error) => Err(io_error("inspect", &absolute, error)),
    }
}

/// Caller holds either the bootstrap lock or the journal lock, and the final name is new.
#[allow(clippy::disallowed_methods)]
fn publish_directory(path: &Path) -> Result<(), ProtocolError> {
    let parent = path
        .parent()
        .ok_or_else(|| ProtocolError::internal("journal directory has no parent"))?;
    let temporary = parent.join(format!(
        "{DIRECTORY_TEMP_PREFIX}{}{TEMP_SUFFIX}",
        Uuid::new_v4()
    ));
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    builder
        .create(&temporary)
        .map_err(|error| io_error("create directory", &temporary, error))?;
    publish(&temporary, path, false)
}

/// On error publication may already have happened. Preserve both names and let the next
/// locked operation reload disk state; callers must not dispatch after this error, unless
/// both outcomes are equally sound (admission's marker write, which only caches a verdict).
#[allow(clippy::disallowed_methods)]
fn publish(source: &Path, destination: &Path, replace: bool) -> Result<(), ProtocolError> {
    #[cfg(feature = "test-util")]
    let _publication = phase_diagnostics::start(Some(destination), "publication_inclusive");
    #[cfg(feature = "test-util")]
    publication_point(PublicationPoint::BeforeRename, source, destination)?;
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING;
        use windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH;
        use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
        let source_wide = lore_base::fs::win_path::to_extended_wide(source);
        let destination_wide = lore_base::fs::win_path::to_extended_wide(destination);
        let flags = MOVEFILE_WRITE_THROUGH
            | if replace {
                MOVEFILE_REPLACE_EXISTING
            } else {
                0
            };
        // SAFETY: Both buffers are live, NUL-terminated UTF-16 paths for this synchronous call.
        // COPY_ALLOWED is deliberately absent: publication must remain on the same volume.
        let result = unsafe { MoveFileExW(source_wide.as_ptr(), destination_wide.as_ptr(), flags) };
        if result == 0 {
            return Err(io_error(
                "publish",
                destination,
                std::io::Error::last_os_error(),
            ));
        }
    }
    #[cfg(not(windows))]
    {
        if !replace && destination.exists() {
            return Err(ProtocolError::internal(
                "journal publication destination already exists",
            ));
        }
        std::fs::rename(source, destination)
            .map_err(|error| io_error("publish", destination, error))?;
    }
    // On Unix this is the actual visible-rename/before-directory-sync boundary. Windows
    // combines publication and write-through in the native call above; its test hook only
    // simulates the split protocol and is not evidence of a native durability failure.
    #[cfg(feature = "test-util")]
    publication_point(
        PublicationPoint::AfterRenameBeforeDirectorySync,
        source,
        destination,
    )?;
    sync_directory(destination.parent())?;
    if source.parent() != destination.parent() {
        sync_directory(source.parent())?;
    }
    #[cfg(feature = "test-util")]
    publication_point(PublicationPoint::AfterRename, source, destination)?;
    Ok(())
}

fn sync_directory(directory: Option<&Path>) -> Result<(), ProtocolError> {
    let directory =
        directory.ok_or_else(|| ProtocolError::internal("journal path has no parent"))?;
    #[cfg(feature = "test-util")]
    publication_point(PublicationPoint::BeforeDirectorySync, directory, directory)?;
    #[cfg(not(windows))]
    std::fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error("sync directory", directory, error))?;
    // Windows publication uses checked MoveFileExW(WRITE_THROUGH), not directory handles.
    #[cfg(windows)]
    let _ = directory;
    #[cfg(feature = "test-util")]
    publication_point(PublicationPoint::AfterDirectorySync, directory, directory)?;
    Ok(())
}

#[allow(clippy::disallowed_methods)]
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ProtocolError> {
    #[cfg(feature = "test-util")]
    let preparation = phase_diagnostics::start(Some(path), "temporary_prepare_remove");
    let mut name = path.as_os_str().to_owned();
    name.push(TEMP_SUFFIX);
    let temporary = PathBuf::from(name);
    // Only the unpublished temporary is removed. Never remove a published generation on error.
    match std::fs::remove_file(&temporary) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(io_error("remove temporary", &temporary, error)),
    }
    let mut options = std::fs::OpenOptions::new();
    #[cfg(feature = "test-util")]
    drop(preparation);
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(feature = "test-util")]
    let create = phase_diagnostics::start(Some(path), "temporary_create");
    let mut file = options
        .open(&temporary)
        .map_err(|error| io_error("create temporary", &temporary, error))?;
    #[cfg(feature = "test-util")]
    drop(create);
    #[cfg(feature = "test-util")]
    let write = phase_diagnostics::start(Some(path), "temporary_write");
    file.write_all(bytes)
        .map_err(|error| io_error("write temporary", &temporary, error))?;
    #[cfg(feature = "test-util")]
    drop(write);
    #[cfg(feature = "test-util")]
    publication_point(PublicationPoint::AfterWrite, &temporary, path)?;
    #[cfg(feature = "test-util")]
    let sync = phase_diagnostics::start(Some(path), "temporary_sync");
    file.sync_all()
        .map_err(|error| io_error("flush temporary", &temporary, error))?;
    #[cfg(feature = "test-util")]
    drop(sync);
    #[cfg(feature = "test-util")]
    publication_point(PublicationPoint::AfterSync, &temporary, path)?;
    #[cfg(feature = "test-util")]
    let close = phase_diagnostics::start(Some(path), "temporary_close");
    drop(file);
    #[cfg(feature = "test-util")]
    drop(close);
    publish(&temporary, path, true)
}

impl RepositoryAttemptStore {
    pub(super) fn load(&self, guard: &FSLock) -> Result<StoredDocument, ProtocolError> {
        let path = self.require_path()?;
        #[cfg(feature = "test-util")]
        let read = phase_diagnostics::start(Some(path), "root_read");
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A missing root with published-generation evidence cannot be read as empty.
                let parent = path
                    .parent()
                    .ok_or_else(|| ProtocolError::internal("journal has no directory"))?;
                for entry in std::fs::read_dir(parent)
                    .map_err(|error| io_error("inspect missing root", parent, error))?
                {
                    let entry =
                        entry.map_err(|error| io_error("inspect missing root", parent, error))?;
                    if entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("attempts-v2-")
                    {
                        return Err(ProtocolError::internal(
                            "journal root missing with generation evidence",
                        ));
                    }
                }
                return Ok(StoredDocument::default());
            }
            Err(error) => return Err(io_error("read", path, error)),
        };
        #[cfg(feature = "test-util")]
        drop(read);
        #[cfg(feature = "test-util")]
        let parse = phase_diagnostics::start(Some(path), "root_parse");
        let (version, body) = bytes
            .split_first()
            .ok_or_else(|| ProtocolError::internal("empty attempt journal is corrupt"))?;
        if !matches!(*version, 1 | ATTEMPT_STORE_VERSION) {
            return Err(ProtocolError::internal(format!(
                "unsupported attempt journal version {version}"
            )));
        }
        let document: StoredDocument =
            serde_json::from_slice(body).map_err(|error| io_error("parse", path, error))?;
        #[cfg(feature = "test-util")]
        drop(parse);
        #[cfg(feature = "test-util")]
        let _validation = phase_diagnostics::start(Some(path), "root_validate_repair_inclusive");
        if *version == 1 {
            return self.migrate(guard, document);
        }
        if !document.attempts.is_empty() {
            return Err(ProtocolError::internal("v2 journal has inline attempts"));
        }
        let generation = self.generation(&document)?;
        for directory in [
            &generation,
            &generation.join("pending"),
            &generation.join("settled"),
        ] {
            if !std::fs::metadata(directory)
                .map_err(|error| io_error("inspect generation", directory, error))?
                .is_dir()
            {
                return Err(ProtocolError::internal(
                    "journal generation directory is missing",
                ));
            }
        }
        // Visibility after a failed Unix rename/fsync is not durability. Re-establish the
        // fixed set of journal directory barriers before another caller can acknowledge
        // dependent work. This does not enumerate or rewrite settled child history.
        sync_directory(Some(&generation.join("settled")))?;
        sync_directory(Some(&generation.join("pending")))?;
        sync_directory(Some(&generation))?;
        sync_directory(path.parent())?;
        Ok(document)
    }

    pub(super) fn load_for_write(&self, guard: &FSLock) -> Result<StoredDocument, ProtocolError> {
        let document = self.load(guard)?;
        if document.generation.is_none() {
            self.migrate(guard, document)
        } else {
            Ok(document)
        }
    }

    pub(super) fn store(
        &self,
        _guard: &FSLock,
        document: &StoredDocument,
    ) -> Result<(), ProtocolError> {
        let mut bytes = vec![ATTEMPT_STORE_VERSION];
        serde_json::to_writer(&mut bytes, document).map_err(|error| {
            ProtocolError::internal(format!("Failed to serialize attempt journal: {error}"))
        })?;
        write_atomic(self.require_path()?, &bytes)
    }

    fn migrate(
        &self,
        guard: &FSLock,
        mut document: StoredDocument,
    ) -> Result<StoredDocument, ProtocolError> {
        // Validate before publishing anything. A failed migration never rewrites the v1 root.
        let mut attempts = HashSet::new();
        for attempt in &mut document.attempts {
            AttemptRecord::try_from(&*attempt)?;
            attempt.attempt_id = parse_attempt_id(&attempt.attempt_id)?.to_string();
            if !attempts.insert(attempt.attempt_id.clone()) {
                return Err(ProtocolError::internal(
                    "duplicate attempt identity in legacy journal",
                ));
            }
        }
        let mut managed = HashMap::new();
        for mut child in std::mem::take(&mut document.managed) {
            child.attempt = parse_attempt_id(&child.attempt)?.to_string();
            child.parent = parse_uuid(&child.parent, "managed parent")?.to_string();
            if managed.insert(child.attempt.clone(), child).is_some() {
                return Err(ProtocolError::internal(
                    "duplicate managed identity in legacy journal",
                ));
            }
        }
        for ownership in &mut document.ownership {
            LockOwnership::try_from(&*ownership)?;
            ownership.attempt_id = parse_attempt_id(&ownership.attempt_id)?.to_string();
        }
        for parent in &mut document.parents {
            parent.id = parse_uuid(&parent.id, "managed parent")?.to_string();
        }
        Self::validate_parents(&document)?;
        let mut children = Vec::with_capacity(document.attempts.len());
        for attempt in std::mem::take(&mut document.attempts) {
            let intent = managed.remove(&attempt.attempt_id);
            let child = StoredChild::new(attempt, intent);
            self.validate_child(&document, &child, &child.attempt.attempt_id)?;
            children.push(child);
        }
        document.generation = Some(Uuid::new_v4().to_string());
        let generation = self.generation(&document)?;
        publish_directory(&generation)?;
        publish_directory(&generation.join("pending"))?;
        publish_directory(&generation.join("settled"))?;
        for child in children {
            let directory = if child.attempt.state.is_unresolved() {
                "pending"
            } else {
                "settled"
            };
            Self::write_child_at(
                &generation
                    .join(directory)
                    .join(format!("{}.json", child.attempt.attempt_id)),
                &child,
            )?;
        }
        // Legacy intent-only rows never become dispatchable children and are never discarded.
        document.managed = managed.into_values().collect();
        document
            .managed
            .sort_by(|left, right| left.attempt.cmp(&right.attempt));
        self.store(guard, &document)?;
        Ok(document)
    }

    fn generation(&self, document: &StoredDocument) -> Result<PathBuf, ProtocolError> {
        let generation = document
            .generation
            .as_deref()
            .ok_or_else(|| ProtocolError::internal("v2 journal generation is missing"))?;
        if Uuid::parse_str(generation)
            .map_err(|_err| ProtocolError::internal("invalid journal generation"))?
            .to_string()
            != generation
        {
            return Err(ProtocolError::internal("noncanonical journal generation"));
        }
        Ok(self
            .require_path()?
            .with_file_name(format!("attempts-v2-{generation}")))
    }

    #[allow(
        clippy::unused_self,
        reason = "the test-util build reads self.path for phase diagnostics"
    )]
    fn validate_child(
        &self,
        document: &StoredDocument,
        child: &StoredChild,
        id: &str,
    ) -> Result<(), ProtocolError> {
        #[cfg(feature = "test-util")]
        let _validation = phase_diagnostics::start(self.path.as_deref(), "child_validate");
        if child.version != ATTEMPT_STORE_VERSION || child.attempt.attempt_id != id {
            return Err(ProtocolError::internal(
                "invalid journal child version or identity",
            ));
        }
        let record = AttemptRecord::try_from(&child.attempt)?;
        if record.attempt_id.to_string() != id {
            return Err(ProtocolError::internal(
                "noncanonical journal child identity",
            ));
        }
        if let Some(managed) = &child.managed
            && (managed.attempt != id
                || !document
                    .parents
                    .iter()
                    .any(|parent| parent.id == managed.parent && parent.version == 1))
        {
            return Err(ProtocolError::internal("invalid managed child binding"));
        }
        Ok(())
    }

    fn child_at(
        &self,
        document: &StoredDocument,
        path: &Path,
        id: &str,
    ) -> Result<Option<StoredChild>, ProtocolError> {
        #[cfg(feature = "test-util")]
        let read = phase_diagnostics::start(Some(path), "child_read");
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error("read child", path, error)),
        };
        #[cfg(feature = "test-util")]
        drop(read);
        #[cfg(feature = "test-util")]
        let parse = phase_diagnostics::start(Some(path), "child_parse");
        let child: StoredChild =
            serde_json::from_slice(&bytes).map_err(|error| io_error("parse child", path, error))?;
        #[cfg(feature = "test-util")]
        drop(parse);
        self.validate_child(document, &child, id)?;
        Ok(Some(child))
    }

    pub(super) fn child(
        &self,
        document: &StoredDocument,
        id: &str,
    ) -> Result<Option<(StoredChild, PathBuf)>, ProtocolError> {
        if document.generation.is_none() {
            return Ok(None);
        }
        // Identity validation precedes path construction, including internal migration callers.
        if parse_attempt_id(id)?.to_string() != id {
            return Err(ProtocolError::internal("noncanonical attempt identity"));
        }
        let generation = self.generation(document)?;
        let pending_path = generation.join("pending").join(format!("{id}.json"));
        let settled_path = generation.join("settled").join(format!("{id}.json"));
        let pending = self.child_at(document, &pending_path, id)?;
        let settled = self.child_at(document, &settled_path, id)?;
        match (pending, settled) {
            (Some(_), Some(_)) => Err(ProtocolError::internal(
                "duplicate journal child in pending and settled",
            )),
            (Some(child), None) => Ok(Some((child, pending_path))),
            (None, Some(child)) if child.attempt.state.is_unresolved() => Err(
                ProtocolError::internal("unresolved child in settled journal"),
            ),
            (None, Some(child)) => Ok(Some((child, settled_path))),
            (None, None) => Ok(None),
        }
    }

    pub(super) fn load_child<'guard>(
        &self,
        guard: &'guard FSLock,
        document: &StoredDocument,
        id: &str,
    ) -> Result<LoadedChild<'guard>, ProtocolError> {
        let (child, path) = match self.child(document, id)? {
            Some((child, path)) => (Some(child), Some(path)),
            None => (None, None),
        };
        Ok(LoadedChild {
            _guard: guard,
            id: id.to_owned(),
            child,
            path,
        })
    }

    pub(super) fn write_child(
        &self,
        document: &StoredDocument,
        child: &StoredChild,
        existing: LoadedChild<'_>,
    ) -> Result<(), ProtocolError> {
        let id = &child.attempt.attempt_id;
        if *id != existing.id {
            return Err(ProtocolError::internal(
                "loaded journal child identity mismatch",
            ));
        }
        self.validate_child(document, child, id)?;
        let generation = self.generation(document)?;
        let pending = generation.join("pending").join(format!("{id}.json"));
        let settled = generation.join("settled").join(format!("{id}.json"));
        if child.attempt.state.is_unresolved() {
            if let Some(path) = existing.path
                && path == settled
            {
                // Never publish unresolved bytes in settled. A crash before the replacement
                // leaves a terminal pending child and acknowledges no new dispatch.
                publish(&settled, &pending, false)?;
            }
            Self::write_child_at(&pending, child)
        } else if let Some(path) = existing.path
            && path == pending
        {
            Self::write_child_at(&pending, child)?;
            publish(&pending, &settled, false)
        } else {
            Self::write_child_at(&settled, child)
        }
    }

    fn write_child_at(path: &Path, child: &StoredChild) -> Result<(), ProtocolError> {
        #[cfg(feature = "test-util")]
        let serialize = phase_diagnostics::start(Some(path), "child_serialize");
        let bytes =
            serde_json::to_vec(child).map_err(|error| io_error("serialize child", path, error))?;
        #[cfg(feature = "test-util")]
        drop(serialize);
        write_atomic(path, &bytes)
    }

    pub(super) fn children(
        &self,
        document: &StoredDocument,
        pending_only: bool,
    ) -> Result<Vec<StoredChild>, ProtocolError> {
        if document.generation.is_none() {
            return Ok(Vec::new());
        }
        let generation = self.generation(document)?;
        let directories: &[&str] = if pending_only {
            &["pending"]
        } else {
            &["pending", "settled"]
        };
        let mut children = Vec::new();
        let mut seen = document
            .managed
            .iter()
            .map(|child| child.attempt.clone())
            .collect::<HashSet<_>>();
        for directory in directories {
            for (id, _) in child_entries(&generation.join(directory))? {
                if !seen.insert(id.clone()) {
                    return Err(ProtocolError::internal("duplicate journal child identity"));
                }
                let (child, _) = self
                    .child(document, &id)?
                    .ok_or_else(|| ProtocolError::internal("journal child disappeared"))?;
                children.push(child);
            }
        }
        Ok(children)
    }

    /// The settled half of `children(document, false)`'s validation, without returning the
    /// children. A settled child this store already validated is parsed again only when its
    /// length or modification time changed, or its parent left the root. Returns the listing it
    /// validated, which `finish_parent` prunes and fingerprints without listing again.
    /// `resolve_unknown` also parses children `seed_settled` trusted without a parent, so the
    /// returned listing names every parent; parent pruning needs that.
    pub(super) fn check_settled(
        &self,
        _guard: &FSLock,
        document: &StoredDocument,
        resolve_unknown: bool,
    ) -> Result<Vec<SettledEntry>, ProtocolError> {
        let Some(current) = document.generation.as_deref() else {
            return Ok(Vec::new());
        };
        let generation = self.generation(document)?;
        let mut seen = document
            .managed
            .iter()
            .map(|child| child.attempt.clone())
            .collect::<HashSet<_>>();
        for (id, _) in child_entries(&generation.join("pending"))? {
            if !seen.insert(id) {
                return Err(ProtocolError::internal("duplicate journal child identity"));
            }
        }
        let parents = document
            .parents
            .iter()
            .filter(|parent| parent.version == 1)
            .map(|parent| parent.id.as_str())
            .collect::<HashSet<_>>();
        let mut cache = self
            .settled
            .lock()
            .map_err(|_err| ProtocolError::internal("settled validation cache poisoned"))?;
        if cache.generation.as_deref() != Some(current) {
            cache.generation = Some(current.to_owned());
            cache.entries.clear();
        }
        let settled = child_entries(&generation.join("settled"))?;
        // A file that left settled must not be trusted if it later returns with old metadata.
        let present = settled.iter().map(|(id, _)| id).collect::<HashSet<_>>();
        cache.entries.retain(|id, _| present.contains(id));
        let mut validated = Vec::with_capacity(settled.len());
        for (id, entry) in settled {
            if !seen.insert(id.clone()) {
                return Err(ProtocolError::internal("duplicate journal child identity"));
            }
            let metadata = entry
                .metadata()
                .map_err(|error| io_error("inspect child", &entry.path(), error))?;
            // A filesystem without modification times always parses.
            let modified = metadata.modified().ok();
            // An unknown parent was present when the marker vouched for it, and a parent leaves
            // the root only through a prune that saw every parent in the listing.
            if let Some(cached) = cache.entries.get(&id).filter(|cached| {
                Some(cached.modified) == modified
                    && cached.len == metadata.len()
                    && match &cached.parent {
                        SettledParent::Unmanaged => true,
                        SettledParent::Managed(parent) => parents.contains(parent.as_str()),
                        SettledParent::Unknown => !resolve_unknown,
                    }
            }) {
                validated.push(SettledEntry {
                    parent: cached.parent.clone(),
                    id,
                    len: metadata.len(),
                    modified,
                });
                continue;
            }
            cache.entries.remove(&id);
            let (child, _) = self
                .child(document, &id)?
                .ok_or_else(|| ProtocolError::internal("journal child disappeared"))?;
            let parent = SettledParent::of(&child);
            if let Some(modified) = modified {
                cache.entries.insert(
                    id.clone(),
                    ValidatedSettled {
                        len: metadata.len(),
                        modified,
                        parent: parent.clone(),
                    },
                );
            }
            validated.push(SettledEntry {
                id,
                len: metadata.len(),
                modified,
                parent,
            });
        }
        Ok(validated)
    }

    /// Trust a settled `listing` the admission marker vouched for without parsing it: a child
    /// the cache does not already hold at that length and mtime is recorded with an unknown
    /// parent. Valid only while every parent in the root is complete, as `begin_parent`
    /// requires, so a later `prune_settled` may age such a child out; it removes no parent while
    /// any unknown one remains.
    pub(super) fn seed_settled(
        &self,
        _guard: &FSLock,
        document: &StoredDocument,
        listing: &[SettledListing],
    ) -> Result<(), ProtocolError> {
        let Some(current) = document.generation.as_deref() else {
            return Ok(());
        };
        let mut cache = self
            .settled
            .lock()
            .map_err(|_err| ProtocolError::internal("settled validation cache poisoned"))?;
        if cache.generation.as_deref() != Some(current) {
            cache.generation = Some(current.to_owned());
            cache.entries.clear();
        }
        let present = listing.iter().map(|(id, _, _)| id).collect::<HashSet<_>>();
        cache.entries.retain(|id, _| present.contains(id));
        for (id, len, modified) in listing {
            let Some(modified) = *modified else {
                continue;
            };
            if cache
                .entries
                .get(id)
                .is_some_and(|cached| cached.len == *len && cached.modified == modified)
            {
                continue;
            }
            cache.entries.insert(
                id.clone(),
                ValidatedSettled {
                    len: *len,
                    modified,
                    parent: SettledParent::Unknown,
                },
            );
        }
        Ok(())
    }

    /// Delete settled children older than [`SETTLED_RETENTION`], at most
    /// [`PRUNE_CHILDREN_PER_CALL`] per call, then drop complete parents nothing references any
    /// more. `settled` must be `check_settled`'s listing under the same guard; the entries that
    /// remain are returned, with `false` when a trusted child failed to parse, so the caller
    /// must not record a marker over them. Best effort: a failure logs and keeps what it could
    /// not prove gone.
    ///
    /// Files go first and the caller's root write comes after, never the reverse. A root that
    /// lost a parent while one of its children survived would fail `validate_child` and close
    /// the write fence. So a parent leaves only when no child named it before this call's
    /// deletes: its last child went in an earlier call, whose deletion a synced directory
    /// (Unix) or that call's write-through root publication (Windows, where NTFS journals
    /// metadata in order) already made durable. A crash at any point leaves every remaining
    /// child bound to a parent in the root. The children of `current`, the parent being
    /// finished, are kept: until its completion is in the root, recovery needs them as
    /// positive settlement evidence.
    // The journal is an authorized writer; it deletes only settled children under its lock.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn prune_settled(
        &self,
        _guard: &FSLock,
        document: &mut StoredDocument,
        settled: Vec<SettledEntry>,
        pending: &[StoredChild],
        current: &str,
    ) -> Result<(Vec<SettledEntry>, bool), ProtocolError> {
        #[cfg(feature = "test-util")]
        let _prune = phase_diagnostics::start(self.path.as_deref(), "settled_prune");
        let Some(cutoff) = std::time::SystemTime::now().checked_sub(SETTLED_RETENTION) else {
            return Ok((settled, true));
        };
        let settled_directory = self.generation(document)?.join("settled");
        let complete = document
            .parents
            .iter()
            .filter(|parent| parent.complete && parent.id != current)
            .map(|parent| parent.id.as_str())
            .collect::<HashSet<_>>();
        // Taken before any delete, so a parent outlives its last child by one call. A child
        // whose parent is unknown might name any parent, so then no parent leaves.
        let all_known = settled
            .iter()
            .all(|entry| !matches!(entry.parent, SettledParent::Unknown));
        let unreferenced = if !all_known {
            HashSet::new()
        } else {
            let referenced = settled
                .iter()
                .filter_map(|entry| entry.parent.name())
                .chain(
                    pending
                        .iter()
                        .filter_map(|child| child.managed.as_ref())
                        .map(|managed| managed.parent.as_str()),
                )
                .chain(document.managed.iter().map(|intent| intent.parent.as_str()))
                .collect::<HashSet<_>>();
            complete
                .iter()
                .filter(|parent| {
                    !referenced.contains(*parent) && parent_created_before(parent, cutoff)
                })
                .map(|parent| (*parent).to_owned())
                .collect::<HashSet<_>>()
        };
        let mut removed = 0u64;
        let mut gone = 0u64;
        let mut failures = 0usize;
        let mut damaged = HashSet::new();
        let mut remaining = Vec::with_capacity(settled.len());
        for mut entry in settled {
            let old = entry.modified.is_some_and(|modified| modified < cutoff);
            if failures >= PRUNE_FAILURES_PER_CALL
                || !old
                || removed + gone >= PRUNE_CHILDREN_PER_CALL
            {
                remaining.push(entry);
                continue;
            }
            if matches!(entry.parent, SettledParent::Unknown) {
                // Bounded by the deletion budget: at most one parse per child this call may
                // delete. A child the marker vouched for that no longer parses is damaged
                // history: keep it and let the caller drop the marker, so the next admission
                // scans in full and closes the write fence on it.
                match self.child(document, &entry.id) {
                    Ok(Some((child, _))) => entry.parent = SettledParent::of(&child),
                    Ok(None) => {
                        gone += 1;
                        continue;
                    }
                    Err(error) => {
                        crate::lore_warn!("Could not read settled attempt {}: {error}", entry.id);
                        damaged.insert(entry.id.clone());
                        failures += 1;
                        remaining.push(entry);
                        continue;
                    }
                }
            }
            if entry
                .parent
                .name()
                .is_some_and(|parent| !complete.contains(parent))
            {
                remaining.push(entry);
                continue;
            }
            let path = settled_directory.join(format!("{}.json", entry.id));
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                // Gone without this call deleting it: leave the count to whoever did.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => gone += 1,
                // One held file must not stop the rest; a directory-wide failure stops soon.
                Err(error) => {
                    crate::lore_warn!("Could not prune settled attempt {}: {error}", entry.id);
                    failures += 1;
                    remaining.push(entry);
                }
            }
        }
        // The cache keeps what this call learned: deleted children leave it, a resolved parent
        // replaces Unknown, and a damaged child leaves it so every later `check_settled` parses
        // it again and fails, rather than trusting it into a new marker.
        let mut cache = self
            .settled
            .lock()
            .map_err(|_err| ProtocolError::internal("settled validation cache poisoned"))?;
        let kept = remaining
            .iter()
            .filter(|entry| !damaged.contains(&entry.id))
            .map(|entry| (&entry.id, &entry.parent))
            .collect::<HashMap<_, _>>();
        cache.entries.retain(|id, cached| {
            let Some(parent) = kept.get(id) else {
                return false;
            };
            if matches!(cached.parent, SettledParent::Unknown) {
                cached.parent = (*parent).clone();
            }
            // Damage under the marker voids what it vouched for: parse the rest again.
            damaged.is_empty() || !matches!(cached.parent, SettledParent::Unknown)
        });
        drop(cache);
        // On Unix this also makes an earlier call's deletes durable if its own sync failed. A
        // failed delete in this call does not matter here: no unreferenced parent named it.
        let durable = if unreferenced.is_empty() && removed == 0 {
            true
        } else if let Err(error) = sync_directory(Some(&settled_directory)) {
            crate::lore_warn!("Could not sync pruned attempt journal: {error}");
            false
        } else {
            true
        };
        let mut pruned_parents = 0u64;
        if durable && !unreferenced.is_empty() {
            let before = document.parents.len();
            document
                .parents
                .retain(|parent| !unreferenced.contains(&parent.id));
            pruned_parents = (before - document.parents.len()) as u64;
        }
        if removed > 0 || pruned_parents > 0 {
            let summary = document.pruned.get_or_insert_with(Default::default);
            summary.children = summary.children.saturating_add(removed);
            summary.parents = summary.parents.saturating_add(pruned_parents);
        }
        Ok((remaining, damaged.is_empty()))
    }
}

/// How long a settled child stays after settlement before `finish_parent` may delete it.
pub(super) const SETTLED_RETENTION: std::time::Duration =
    std::time::Duration::from_secs(7 * 24 * 60 * 60);

/// Bound on one `finish_parent`'s deletions, so a large backlog drains over many calls.
pub(super) const PRUNE_CHILDREN_PER_CALL: u64 = 1024;

/// Failed reads or deletes after which one `finish_parent` stops pruning.
const PRUNE_FAILURES_PER_CALL: usize = 8;

/// Complete parents old enough to prune that make `begin_parent` parse in full, so the next
/// `finish_parent` knows every child's parent and can remove them. Each costs one root row.
pub(super) const FULL_SCAN_PARENT_THRESHOLD: usize = 256;

/// Longest gap between two full parses at `begin_parent`.
pub(super) const FULL_SCAN_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

impl RepositoryAttemptStore {
    /// Whether `begin_parent` must parse every settled child even when the marker matches:
    /// no full parse is recorded, the last is older than [`FULL_SCAN_INTERVAL`] (or in the
    /// future, after a clock change), or [`FULL_SCAN_PARENT_THRESHOLD`] parents are waiting.
    pub(super) fn full_scan_due(document: &StoredDocument) -> bool {
        let now = std::time::SystemTime::now();
        let interval = i64::try_from(FULL_SCAN_INTERVAL.as_millis()).unwrap_or(i64::MAX);
        let current = now_unix_millis();
        let stale = document
            .pruned
            .as_ref()
            .and_then(|pruned| pruned.full_scan_unix_millis)
            .is_none_or(|last| last > current || current.saturating_sub(last) >= interval);
        stale
            || now.checked_sub(SETTLED_RETENTION).is_some_and(|cutoff| {
                document
                    .parents
                    .iter()
                    .filter(|parent| parent.complete && parent_created_before(&parent.id, cutoff))
                    .count()
                    >= FULL_SCAN_PARENT_THRESHOLD
            })
    }
}

/// Whether a parent identity is a `UUIDv7` minted before `cutoff`. Any other identity has no
/// creation time, so it is never old enough to prune.
fn parent_created_before(id: &str, cutoff: std::time::SystemTime) -> bool {
    Uuid::parse_str(id)
        .ok()
        .filter(|uuid| uuid.get_version_num() == 7)
        .and_then(|uuid| uuid.get_timestamp())
        .is_some_and(|timestamp| {
            let (seconds, nanos) = timestamp.to_unix();
            std::time::UNIX_EPOCH
                .checked_add(std::time::Duration::new(seconds, nanos))
                .is_some_and(|created| created < cutoff)
        })
}

/// One settled child as `check_settled` validated it.
pub(super) struct SettledEntry {
    id: String,
    len: u64,
    modified: Option<std::time::SystemTime>,
    parent: SettledParent,
}

/// A settled child's name, length and modification time, from one directory listing.
pub(super) type SettledListing = (String, u64, Option<std::time::SystemTime>);

/// The managed parent a validated settled child names.
#[derive(Clone)]
pub(super) enum SettledParent {
    /// No managed intent.
    Unmanaged,
    Managed(String),
    /// Trusted through the admission marker without a parse; see `seed_settled`.
    Unknown,
}

impl SettledParent {
    fn of(child: &StoredChild) -> Self {
        child.managed.as_ref().map_or(Self::Unmanaged, |managed| {
            Self::Managed(managed.parent.clone())
        })
    }

    fn name(&self) -> Option<&str> {
        match self {
            Self::Managed(parent) => Some(parent),
            Self::Unmanaged | Self::Unknown => None,
        }
    }
}

/// Bump when the full scan accepts less than before (a stricter `validate_child` or
/// `children` rule), so markers written under the weaker rules stop matching.
const SETTLED_FINGERPRINT_VERSION: u32 = 1;

impl RepositoryAttemptStore {
    /// Identity of the settled history that a full scan would read, from one directory
    /// enumeration and no child opens: generation, parent and legacy-intent identities, and each
    /// settled child's name, length and modification time. Every journal writer replaces a
    /// child by rename, so any add, move or rewrite changes it. Accepted residual: a rewrite by
    /// a non-Lore writer that keeps name, length and mtime is not seen until recovery's full
    /// scan. `None` (no generation, or no usable mtime) means always scan in full.
    pub(super) fn settled_fingerprint(
        &self,
        _guard: &FSLock,
        document: &StoredDocument,
    ) -> Result<Option<StoredValidation>, ProtocolError> {
        if document.generation.is_none() {
            return Ok(None);
        }
        #[cfg(feature = "test-util")]
        let _fingerprint = phase_diagnostics::start(self.path.as_deref(), "settled_fingerprint");
        let mut settled = self.settled_listing(document)?;
        Ok(Self::fingerprint_of(document, &mut settled))
    }

    /// One enumeration of the settled directory, with no child opens.
    pub(super) fn settled_listing(
        &self,
        document: &StoredDocument,
    ) -> Result<Vec<SettledListing>, ProtocolError> {
        if document.generation.is_none() {
            return Ok(Vec::new());
        }
        let generation = self.generation(document)?;
        let mut settled = Vec::new();
        for (id, entry) in child_entries(&generation.join("settled"))? {
            let metadata = entry
                .metadata()
                .map_err(|error| io_error("inspect child", &entry.path(), error))?;
            settled.push((id, metadata.len(), metadata.modified().ok()));
        }
        Ok(settled)
    }

    /// The marker for settled history `check_settled` (and any pruning after it) just validated,
    /// from the same listing, so `finish_parent` records it without a second enumeration.
    pub(super) fn validated_fingerprint(
        _guard: &FSLock,
        document: &StoredDocument,
        settled: &[SettledEntry],
    ) -> Option<StoredValidation> {
        document.generation.as_ref()?;
        Self::fingerprint_of(
            document,
            &mut settled
                .iter()
                .map(|entry| (entry.id.clone(), entry.len, entry.modified))
                .collect::<Vec<_>>(),
        )
    }

    /// One hash over a settled listing, which it sorts. Every marker goes through here, so a
    /// marker `finish_parent` records matches the one the next admission computes from disk.
    pub(super) fn fingerprint_of(
        document: &StoredDocument,
        settled: &mut [SettledListing],
    ) -> Option<StoredValidation> {
        let current = document.generation.as_deref()?;
        let mut hasher = blake3::Hasher::new();
        let mut field = |bytes: &[u8]| {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        field(b"lore-attempt-settled");
        field(&SETTLED_FINGERPRINT_VERSION.to_le_bytes());
        field(&[ATTEMPT_STORE_VERSION]);
        field(current.as_bytes());
        field(&(document.parents.len() as u64).to_le_bytes());
        for parent in &document.parents {
            field(parent.id.as_bytes());
            field(&parent.version.to_le_bytes());
        }
        let mut legacy = document
            .managed
            .iter()
            .map(|intent| (intent.attempt.as_str(), intent.parent.as_str()))
            .collect::<Vec<_>>();
        legacy.sort_unstable();
        field(&(legacy.len() as u64).to_le_bytes());
        for (attempt, parent) in legacy {
            field(attempt.as_bytes());
            field(parent.as_bytes());
        }
        settled.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        field(&(settled.len() as u64).to_le_bytes());
        for (id, len, modified) in settled.iter() {
            let modified = modified
                .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())?;
            field(id.as_bytes());
            field(&len.to_le_bytes());
            field(&modified.as_nanos().to_le_bytes());
        }
        Some(StoredValidation {
            version: SETTLED_FINGERPRINT_VERSION,
            fingerprint: hasher.finalize().to_hex().to_string(),
        })
    }
}

/// Settled children one store instance has fully validated in this process.
#[derive(Default)]
pub(super) struct SettledCache {
    generation: Option<String>,
    entries: HashMap<String, ValidatedSettled>,
}

struct ValidatedSettled {
    len: u64,
    modified: std::time::SystemTime,
    parent: SettledParent,
}

/// Child identities in one journal directory, skipping unpublished temporaries.
fn child_entries(path: &Path) -> Result<Vec<(String, std::fs::DirEntry)>, ProtocolError> {
    let mut entries = Vec::new();
    for entry in
        std::fs::read_dir(path).map_err(|error| io_error("enumerate children", path, error))?
    {
        let entry = entry.map_err(|error| io_error("enumerate child", path, error))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| ProtocolError::internal("invalid journal child filename"))?;
        if name.ends_with(TEMP_SUFFIX) {
            continue;
        }
        let id = name
            .strip_suffix(".json")
            .ok_or_else(|| ProtocolError::internal("unexpected journal child filename"))?
            .to_owned();
        entries.push((id, entry));
    }
    Ok(entries)
}
