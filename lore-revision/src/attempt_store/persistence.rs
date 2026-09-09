// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Versioned journal persistence. All child operations hold the root's FSLock.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Write;

use super::*;

pub(crate) const BOOTSTRAP_FILE: &str = ".lore-workflow.bootstrap";
pub(crate) const BOOTSTRAP_LOCK_FILE: &str = ".lore-workflow.bootstrap.lock";
const DIRECTORY_TEMP_PREFIX: &str = ".lore-workflow.directory.";

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicationPoint {
    AfterWrite,
    AfterSync,
    BeforeRename,
    AfterRenameBeforeDirectorySync,
    BeforeDirectorySync,
    AfterDirectorySync,
    AfterRename,
}

#[cfg(test)]
type PublicationCallback =
    Arc<dyn Fn(PublicationPoint, &Path, &Path) -> Result<(), ProtocolError> + Send + Sync>;

#[cfg(test)]
fn publication_probes() -> &'static std::sync::Mutex<HashMap<PathBuf, PublicationCallback>> {
    static PROBES: std::sync::OnceLock<std::sync::Mutex<HashMap<PathBuf, PublicationCallback>>> =
        std::sync::OnceLock::new();
    PROBES.get_or_init(Default::default)
}

#[cfg(test)]
pub(super) struct PublicationProbe {
    root: PathBuf,
}

#[cfg(test)]
impl Drop for PublicationProbe {
    fn drop(&mut self) {
        if let Ok(mut probes) = publication_probes().lock() {
            probes.remove(&self.root);
        }
    }
}

#[cfg(test)]
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

#[cfg(test)]
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
    #[cfg(test)]
    let repair = phase_diagnostics::start(
        Some(&absolute),
        if cfg!(windows) {
            "ancestor_repair_windows_test_only"
        } else {
            "ancestor_repair_unix"
        },
    );
    #[cfg(any(not(windows), test))]
    for ancestor in parent.parent().into_iter().flat_map(Path::ancestors) {
        let bootstrap = ancestor.join(BOOTSTRAP_LOCK_FILE);
        match std::fs::metadata(&bootstrap) {
            Ok(_) => {
                let _repair = FSLock::acquire_file_lock(ancestor.join(BOOTSTRAP_FILE))
                    .await
                    .map_err(|error| io_error("lock ancestor bootstrap", ancestor, error))?;
                sync_directory(Some(ancestor))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(io_error("inspect ancestor bootstrap", &bootstrap, error)),
        }
    }
    #[cfg(test)]
    drop(repair);
    #[cfg(test)]
    let wait = phase_diagnostics::start(Some(&absolute), "bootstrap_fslock_wait");
    let _bootstrap = FSLock::acquire_file_lock(parent.join(BOOTSTRAP_FILE))
        .await
        .map_err(|error| io_error("lock bootstrap for", &absolute, error))?;
    #[cfg(test)]
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
/// locked operation reload disk state; callers must not dispatch after this error.
#[allow(clippy::disallowed_methods)]
fn publish(source: &Path, destination: &Path, replace: bool) -> Result<(), ProtocolError> {
    #[cfg(test)]
    let _publication = phase_diagnostics::start(Some(destination), "publication_inclusive");
    #[cfg(test)]
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
    #[cfg(test)]
    publication_point(
        PublicationPoint::AfterRenameBeforeDirectorySync,
        source,
        destination,
    )?;
    sync_directory(destination.parent())?;
    if source.parent() != destination.parent() {
        sync_directory(source.parent())?;
    }
    #[cfg(test)]
    publication_point(PublicationPoint::AfterRename, source, destination)?;
    Ok(())
}

fn sync_directory(directory: Option<&Path>) -> Result<(), ProtocolError> {
    let directory =
        directory.ok_or_else(|| ProtocolError::internal("journal path has no parent"))?;
    #[cfg(test)]
    publication_point(PublicationPoint::BeforeDirectorySync, directory, directory)?;
    #[cfg(not(windows))]
    std::fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error("sync directory", directory, error))?;
    // Windows publication uses checked MoveFileExW(WRITE_THROUGH), not directory handles.
    #[cfg(windows)]
    let _ = directory;
    #[cfg(test)]
    publication_point(PublicationPoint::AfterDirectorySync, directory, directory)?;
    Ok(())
}

#[allow(clippy::disallowed_methods)]
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ProtocolError> {
    #[cfg(test)]
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
    #[cfg(test)]
    drop(preparation);
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(test)]
    let create = phase_diagnostics::start(Some(path), "temporary_create");
    let mut file = options
        .open(&temporary)
        .map_err(|error| io_error("create temporary", &temporary, error))?;
    #[cfg(test)]
    drop(create);
    #[cfg(test)]
    let write = phase_diagnostics::start(Some(path), "temporary_write");
    file.write_all(bytes)
        .map_err(|error| io_error("write temporary", &temporary, error))?;
    #[cfg(test)]
    drop(write);
    #[cfg(test)]
    publication_point(PublicationPoint::AfterWrite, &temporary, path)?;
    #[cfg(test)]
    let sync = phase_diagnostics::start(Some(path), "temporary_sync");
    file.sync_all()
        .map_err(|error| io_error("flush temporary", &temporary, error))?;
    #[cfg(test)]
    drop(sync);
    #[cfg(test)]
    publication_point(PublicationPoint::AfterSync, &temporary, path)?;
    #[cfg(test)]
    let close = phase_diagnostics::start(Some(path), "temporary_close");
    drop(file);
    #[cfg(test)]
    drop(close);
    publish(&temporary, path, true)
}

impl RepositoryAttemptStore {
    pub(super) fn load(&self, guard: &FSLock) -> Result<StoredDocument, ProtocolError> {
        let path = self.require_path()?;
        #[cfg(test)]
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
        #[cfg(test)]
        drop(read);
        #[cfg(test)]
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
        #[cfg(test)]
        drop(parse);
        #[cfg(test)]
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
        self.validate_parents(&document)?;
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
            self.write_child_at(
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
            .map_err(|_| ProtocolError::internal("invalid journal generation"))?
            .to_string()
            != generation
        {
            return Err(ProtocolError::internal("noncanonical journal generation"));
        }
        Ok(self
            .require_path()?
            .with_file_name(format!("attempts-v2-{generation}")))
    }

    fn validate_child(
        &self,
        document: &StoredDocument,
        child: &StoredChild,
        id: &str,
    ) -> Result<(), ProtocolError> {
        #[cfg(test)]
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
        #[cfg(test)]
        let read = phase_diagnostics::start(Some(path), "child_read");
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error("read child", path, error)),
        };
        #[cfg(test)]
        drop(read);
        #[cfg(test)]
        let parse = phase_diagnostics::start(Some(path), "child_parse");
        let child: StoredChild =
            serde_json::from_slice(&bytes).map_err(|error| io_error("parse child", path, error))?;
        #[cfg(test)]
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
            self.write_child_at(&pending, child)
        } else if let Some(path) = existing.path
            && path == pending
        {
            self.write_child_at(&pending, child)?;
            publish(&pending, &settled, false)
        } else {
            self.write_child_at(&settled, child)
        }
    }

    fn write_child_at(&self, path: &Path, child: &StoredChild) -> Result<(), ProtocolError> {
        #[cfg(test)]
        let serialize = phase_diagnostics::start(Some(path), "child_serialize");
        let bytes =
            serde_json::to_vec(child).map_err(|error| io_error("serialize child", path, error))?;
        #[cfg(test)]
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
            let path = generation.join(directory);
            for entry in std::fs::read_dir(&path)
                .map_err(|error| io_error("enumerate children", &path, error))?
            {
                let entry = entry.map_err(|error| io_error("enumerate child", &path, error))?;
                let name = entry.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| ProtocolError::internal("invalid journal child filename"))?;
                if name.ends_with(TEMP_SUFFIX) {
                    continue;
                }
                let id = name
                    .strip_suffix(".json")
                    .ok_or_else(|| ProtocolError::internal("unexpected journal child filename"))?;
                if !seen.insert(id.to_owned()) {
                    return Err(ProtocolError::internal("duplicate journal child identity"));
                }
                let (child, _) = self
                    .child(document, id)?
                    .ok_or_else(|| ProtocolError::internal("journal child disappeared"))?;
                children.push(child);
            }
        }
        Ok(children)
    }
}
