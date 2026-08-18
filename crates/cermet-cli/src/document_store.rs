//! Safe Unix repository-root store for the fixed `CERMET.md` proposal file.

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rand::random;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::cermet_document::MAX_DOCUMENT_BYTES;

const DOCUMENT_NAME: &CStr = c"CERMET.md";
const GIT_NAME: &CStr = c".git";
const PARENT_NAME: &CStr = c"..";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, Eq)]
pub struct FilePreimage {
    pub device: u64,
    pub inode: u64,
    pub len: u64,
    pub sha256: [u8; 32],
    mode: u32,
    change_cookie: MetadataChangeCookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataChangeCookie {
    seconds: i64,
    nanoseconds: i64,
}

impl PartialEq for FilePreimage {
    fn eq(&self, other: &Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.len == other.len
            && self.sha256 == other.sha256
    }
}

impl FilePreimage {
    fn exact_state_matches(&self, other: &Self) -> bool {
        self == other && self.mode == other.mode && self.change_cookie == other.change_cookie
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentRead {
    pub bytes: Vec<u8>,
    pub preimage: FilePreimage,
}

impl DocumentRead {
    pub fn exact_state_matches(&self, other: &Self) -> bool {
        self.preimage.exact_state_matches(&other.preimage) && self.bytes == other.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    Missing,
    Present(DocumentRead),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationOperation {
    Create,
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationOutcome {
    Created,
    Replaced,
    Interfered(PublicationOperation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationDurability {
    Durable,
    Uncertain(String),
    NotClaimedInterference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationModeStatus {
    Applied,
    Failed(String),
    NotClaimedInterference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TempCleanupStatus {
    Complete,
    NotRequired,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalDestinationState {
    Missing,
    Present(DocumentRead),
    Unreadable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationReport {
    pub outcome: PublicationOutcome,
    pub durability: PublicationDurability,
    pub destination_mode: DestinationModeStatus,
    pub temp_cleanup: TempCleanupStatus,
    pub source_interference_detected: bool,
    pub pre_rename_edit_detected: bool,
    pub final_interference_detected: bool,
    pub final_state: FinalDestinationState,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("no physical Git repository contains the starting path")]
    NotInGitRepository,
    #[error("CERMET.md already exists; refusing to clobber it")]
    AlreadyExists,
    #[error("CERMET.md is not a bounded regular file; refusing")]
    InvalidFile,
    #[error("CERMET.md changed since it was read; refusing to replace it")]
    PreimageChanged,
    #[error("the physical repository root changed while it was being opened; refusing")]
    RootSubstituted,
    #[error("the nearest .git marker exists but is not a readable regular file or directory")]
    InvalidGitMarker,
    #[error("repository file operation failed: {0}")]
    Io(#[from] std::io::Error),
}

pub struct DocumentStore {
    root: File,
    root_path: PathBuf,
    root_identity: DirectoryIdentity,
}

struct HeldAncestor {
    directory: File,
    path: PathBuf,
}

struct ExpectedAncestor {
    path: PathBuf,
    identity: DirectoryIdentity,
}

impl DocumentStore {
    pub fn discover(start: &Path) -> Result<Self, StoreError> {
        Self::discover_impl(start, |_| {}, |_, _| {})
    }

    #[cfg(test)]
    fn discover_with_test_hook<F>(start: &Path, before_root_open: F) -> Result<Self, StoreError>
    where
        F: FnMut(&Path),
    {
        Self::discover_impl(start, before_root_open, |_, _| {})
    }

    #[cfg(test)]
    fn discover_with_ancestor_test_hook<F>(
        start: &Path,
        before_ascend: F,
    ) -> Result<Self, StoreError>
    where
        F: FnMut(&Path, usize),
    {
        Self::discover_impl(start, |_| {}, before_ascend)
    }

    fn discover_impl<B, A>(
        start: &Path,
        mut before_start_open: B,
        mut before_ascend: A,
    ) -> Result<Self, StoreError>
    where
        B: FnMut(&Path),
        A: FnMut(&Path, usize),
    {
        let physical = std::fs::canonicalize(start)?;
        let metadata = std::fs::metadata(&physical)?;
        let mut current_path = if metadata.is_dir() {
            physical
        } else {
            physical
                .parent()
                .ok_or(StoreError::NotInGitRepository)?
                .to_path_buf()
        };
        let expected_chain = physical_ancestor_snapshot(&current_path)?;
        before_start_open(&current_path);
        let mut current = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&current_path)?;
        if directory_identity(&current.metadata()?) != expected_chain[0].identity {
            return Err(StoreError::RootSubstituted);
        }

        let mut chain = Vec::new();
        let mut ancestor_index = 0usize;
        loop {
            let parent = openat(
                &current,
                PARENT_NAME,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )?;
            let at_filesystem_root = same_file(&current.metadata()?, &parent.metadata()?);
            chain.push(HeldAncestor {
                directory: current,
                path: current_path.clone(),
            });
            if at_filesystem_root {
                if ancestor_index + 1 != expected_chain.len() {
                    return Err(StoreError::RootSubstituted);
                }
                break;
            }
            ancestor_index += 1;
            let expected_parent = expected_chain
                .get(ancestor_index)
                .ok_or(StoreError::RootSubstituted)?;
            if directory_identity(&parent.metadata()?) != expected_parent.identity {
                return Err(StoreError::RootSubstituted);
            }
            current_path = expected_parent.path.clone();
            current = parent;
        }

        for (depth, ancestor) in chain.into_iter().enumerate() {
            match git_marker_state(&ancestor.directory)? {
                GitMarkerState::Present => {
                    let reported = std::fs::metadata(&ancestor.path)
                        .map_err(|_| StoreError::RootSubstituted)?;
                    let opened = ancestor.directory.metadata()?;
                    if !same_file(&reported, &opened) {
                        return Err(StoreError::RootSubstituted);
                    }
                    return Ok(Self {
                        root: ancestor.directory,
                        root_path: ancestor.path,
                        root_identity: directory_identity(&opened),
                    });
                }
                GitMarkerState::Missing => {}
            }
            before_ascend(&ancestor.path, depth);
        }
        Err(StoreError::NotInGitRepository)
    }

    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    pub fn root_identity(&self) -> DirectoryIdentity {
        self.root_identity
    }

    pub fn read(&self) -> Result<ReadOutcome, StoreError> {
        let Some(mut file) = self.open_document()? else {
            return Ok(ReadOutcome::Missing);
        };
        read_regular_bounded(&mut file).map(ReadOutcome::Present)
    }

    pub fn create(&self, bytes: &[u8]) -> Result<PublicationReport, StoreError> {
        self.create_impl(
            bytes,
            |_| {},
            |temp| temp.unlink_if_same(),
            || self.root.sync_all(),
            |_, _| {},
            || {},
        )
    }

    #[cfg(test)]
    fn create_with_test_hooks<B, C, S, A, F>(
        &self,
        bytes: &[u8],
        before_publication: B,
        cleanup: C,
        sync_directory: S,
        after_publication: A,
        after_sync: F,
    ) -> Result<PublicationReport, StoreError>
    where
        B: FnOnce(&TempEntry<'_>),
        C: FnOnce(&TempEntry<'_>) -> io::Result<()>,
        S: FnOnce() -> io::Result<()>,
        A: FnOnce(&File, &TempEntry<'_>),
        F: FnOnce(),
    {
        self.create_impl(
            bytes,
            before_publication,
            cleanup,
            sync_directory,
            after_publication,
            after_sync,
        )
    }

    fn create_impl<B, C, S, A, F>(
        &self,
        bytes: &[u8],
        before_publication: B,
        cleanup: C,
        sync_directory: S,
        after_publication: A,
        after_sync: F,
    ) -> Result<PublicationReport, StoreError>
    where
        B: FnOnce(&TempEntry<'_>),
        C: FnOnce(&TempEntry<'_>) -> io::Result<()>,
        S: FnOnce() -> io::Result<()>,
        A: FnOnce(&File, &TempEntry<'_>),
        F: FnOnce(),
    {
        validate_write_size(bytes)?;
        let (mut file, mut temp) = self.create_temp()?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let intended = read_regular_bounded(&mut file)?;
        if intended.bytes != bytes {
            return Err(StoreError::PreimageChanged);
        }
        before_publication(&temp);
        match linkat(&self.root, temp.name.as_c_str(), DOCUMENT_NAME) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(StoreError::AlreadyExists)
            }
            Err(error) => return Err(StoreError::Io(error)),
        }
        after_publication(&file, &temp);

        let mut durability_errors = Vec::new();
        let mut bound_destination = self.bound_destination(&intended);
        let source_interference_detected = bound_destination.is_none();
        let temp_cleanup = match cleanup(&temp) {
            Ok(()) => TempCleanupStatus::Complete,
            Err(error) => TempCleanupStatus::Failed(error.to_string()),
        };
        temp.armed = false;
        let (destination_mode, expected_final) = match bound_destination.as_mut() {
            Some(destination) => apply_destination_mode(destination, 0o644, &mut durability_errors),
            None => (DestinationModeStatus::NotClaimedInterference, None),
        };
        if let Err(error) = sync_directory() {
            durability_errors.push(format!("repository directory fsync failed: {error}"));
        }
        after_sync();
        Ok(PublicationClaims {
            operation: PublicationOperation::Create,
            clean_outcome: PublicationOutcome::Created,
            clean_durability: durability_status(durability_errors),
            clean_mode: destination_mode,
            temp_cleanup,
            source_interference_detected,
            pre_rename_edit_detected: false,
        }
        .finish(self.final_destination_state(), expected_final.as_ref()))
    }

    pub fn replace(
        &self,
        expected: &FilePreimage,
        bytes: &[u8],
    ) -> Result<PublicationReport, StoreError> {
        self.replace_impl(
            expected,
            bytes,
            || {},
            || {},
            || self.root.sync_all(),
            || {},
        )
    }

    #[cfg(test)]
    fn replace_with_test_hooks<B, W, S, A>(
        &self,
        expected: &FilePreimage,
        bytes: &[u8],
        before_recheck: B,
        in_rename_window: W,
        sync_directory: S,
        after_rename: A,
    ) -> Result<PublicationReport, StoreError>
    where
        B: FnOnce(),
        W: FnOnce(),
        S: FnOnce() -> io::Result<()>,
        A: FnOnce(),
    {
        self.replace_impl(
            expected,
            bytes,
            before_recheck,
            in_rename_window,
            sync_directory,
            after_rename,
        )
    }

    fn replace_impl<B, W, S, A>(
        &self,
        expected: &FilePreimage,
        bytes: &[u8],
        before_recheck: B,
        in_rename_window: W,
        sync_directory: S,
        after_rename: A,
    ) -> Result<PublicationReport, StoreError>
    where
        B: FnOnce(),
        W: FnOnce(),
        S: FnOnce() -> io::Result<()>,
        A: FnOnce(),
    {
        validate_write_size(bytes)?;
        let (mut file, mut temp) = self.create_temp()?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let intended = read_regular_bounded(&mut file)?;
        if intended.bytes != bytes {
            return Err(StoreError::PreimageChanged);
        }

        before_recheck();
        let Some(mut rechecked_file) = self.open_document()? else {
            return Err(StoreError::PreimageChanged);
        };
        let current = read_regular_bounded(&mut rechecked_file)?;
        if !current.preimage.exact_state_matches(expected) {
            return Err(StoreError::PreimageChanged);
        }
        in_rename_window();
        renameat(&self.root, temp.name.as_c_str(), DOCUMENT_NAME)?;
        temp.armed = false;
        let pre_rename_edit_detected = match read_regular_bounded(&mut rechecked_file) {
            // Renaming over the source updates its ctime, so only its stable identity and bytes can
            // distinguish a hostile in-place edit through this now-unlinked fd.
            Ok(after) => after.preimage != current.preimage,
            Err(_) => true,
        };

        let mut durability_errors = Vec::new();
        let mut bound_destination = self.bound_destination(&intended);
        let source_interference_detected = bound_destination.is_none();
        let (destination_mode, expected_final) = match bound_destination.as_mut() {
            Some(destination) => {
                apply_destination_mode(destination, expected.mode, &mut durability_errors)
            }
            None => (DestinationModeStatus::NotClaimedInterference, None),
        };
        if let Err(error) = sync_directory() {
            durability_errors.push(format!("repository directory fsync failed: {error}"));
        }
        after_rename();
        Ok(PublicationClaims {
            operation: PublicationOperation::Replace,
            clean_outcome: PublicationOutcome::Replaced,
            clean_durability: durability_status(durability_errors),
            clean_mode: destination_mode,
            temp_cleanup: TempCleanupStatus::NotRequired,
            source_interference_detected,
            pre_rename_edit_detected,
        }
        .finish(self.final_destination_state(), expected_final.as_ref()))
    }

    fn create_temp(&self) -> Result<(File, TempEntry<'_>), StoreError> {
        for _ in 0..16 {
            let name = CString::new(format!(".cermet-document.{:032x}", random::<u128>()))
                .expect("generated temp name has no NUL");
            match openat(
                &self.root,
                &name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            ) {
                Ok(file) => {
                    let entry = TempEntry {
                        root: &self.root,
                        name,
                        identity: directory_identity(&file.metadata()?),
                        armed: true,
                    };
                    return Ok((file, entry));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(StoreError::Io(error)),
            }
        }
        Err(StoreError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate an exclusive repository temporary file",
        )))
    }

    fn open_document(&self) -> Result<Option<File>, StoreError> {
        match openat(
            &self.root,
            DOCUMENT_NAME,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        ) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) if is_special_open_error(&error) => Err(StoreError::InvalidFile),
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    fn final_destination_state(&self) -> FinalDestinationState {
        match self.read() {
            Ok(ReadOutcome::Missing) => FinalDestinationState::Missing,
            Ok(ReadOutcome::Present(read)) => FinalDestinationState::Present(read),
            Err(error) => FinalDestinationState::Unreadable(error.to_string()),
        }
    }

    fn bound_destination(&self, intended: &DocumentRead) -> Option<File> {
        let mut destination = self.open_document().ok().flatten()?;
        let actual = read_regular_bounded(&mut destination).ok()?;
        publication_source_matches(&actual, intended).then_some(destination)
    }
}

fn read_regular_bounded(file: &mut File) -> Result<DocumentRead, StoreError> {
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.len() > MAX_DOCUMENT_BYTES as u64 {
        return Err(StoreError::InvalidFile);
    }
    file.seek(SeekFrom::Start(0))?;
    let bytes = read_observed_length(file, before.len())?;
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(StoreError::PreimageChanged);
    }
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    Ok(DocumentRead {
        bytes,
        preimage: FilePreimage {
            device: before.dev(),
            inode: before.ino(),
            len: before.len(),
            sha256,
            mode: before.mode() & 0o7777,
            change_cookie: metadata_change_cookie(&before),
        },
    })
}

fn read_observed_length<R: Read>(reader: &mut R, observed_len: u64) -> Result<Vec<u8>, StoreError> {
    if observed_len > MAX_DOCUMENT_BYTES as u64 {
        return Err(StoreError::InvalidFile);
    }
    let mut bytes = Vec::with_capacity((observed_len as usize).min(MAX_DOCUMENT_BYTES));
    reader
        .take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(StoreError::InvalidFile);
    }
    if bytes.len() as u64 != observed_len {
        return Err(StoreError::PreimageChanged);
    }
    Ok(bytes)
}

struct TempEntry<'a> {
    root: &'a File,
    name: CString,
    identity: DirectoryIdentity,
    armed: bool,
}

impl TempEntry<'_> {
    fn unlink_if_same(&self) -> io::Result<()> {
        let file = openat(
            self.root,
            self.name.as_c_str(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        )?;
        let actual = directory_identity(&file.metadata()?);
        if actual != self.identity {
            return Err(io::Error::other(
                "temporary path no longer names the created inode",
            ));
        }
        unlinkat(self.root, self.name.as_c_str())
    }
}

impl Drop for TempEntry<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.unlink_if_same();
        }
    }
}

fn validate_write_size(bytes: &[u8]) -> Result<(), StoreError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        Err(StoreError::InvalidFile)
    } else {
        Ok(())
    }
}

enum GitMarkerState {
    Missing,
    Present,
}

fn git_marker_state(root: &File) -> Result<GitMarkerState, StoreError> {
    let file = match openat(
        root,
        GIT_NAME,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(GitMarkerState::Missing)
        }
        Err(error) => return Err(StoreError::Io(error)),
    };
    let metadata = file.metadata()?;
    if metadata.file_type().is_file() || metadata.file_type().is_dir() {
        Ok(GitMarkerState::Present)
    } else {
        Err(StoreError::InvalidGitMarker)
    }
}

fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn directory_identity(metadata: &std::fs::Metadata) -> DirectoryIdentity {
    DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn physical_ancestor_snapshot(start: &Path) -> Result<Vec<ExpectedAncestor>, StoreError> {
    let mut path = start.to_path_buf();
    let mut ancestors = Vec::new();
    loop {
        let metadata = std::fs::metadata(&path)?;
        if !metadata.file_type().is_dir() {
            return Err(StoreError::RootSubstituted);
        }
        ancestors.push(ExpectedAncestor {
            path: path.clone(),
            identity: directory_identity(&metadata),
        });
        if !path.pop() {
            break;
        }
    }
    Ok(ancestors)
}

fn publication_source_matches(actual: &DocumentRead, intended: &DocumentRead) -> bool {
    actual.preimage == intended.preimage && actual.bytes == intended.bytes
}

fn publication_final_matches(actual: &DocumentRead, expected: &DocumentRead) -> bool {
    actual.exact_state_matches(expected)
}

fn metadata_change_cookie(metadata: &std::fs::Metadata) -> MetadataChangeCookie {
    MetadataChangeCookie {
        seconds: metadata.ctime(),
        nanoseconds: metadata.ctime_nsec(),
    }
}

struct PublicationClaims {
    operation: PublicationOperation,
    clean_outcome: PublicationOutcome,
    clean_durability: PublicationDurability,
    clean_mode: DestinationModeStatus,
    temp_cleanup: TempCleanupStatus,
    source_interference_detected: bool,
    pre_rename_edit_detected: bool,
}

impl PublicationClaims {
    fn finish(
        self,
        final_state: FinalDestinationState,
        expected_final: Option<&DocumentRead>,
    ) -> PublicationReport {
        let final_interference_detected = match (&final_state, expected_final) {
            (FinalDestinationState::Present(actual), Some(expected)) => {
                !publication_final_matches(actual, expected)
            }
            (FinalDestinationState::Present(_), None)
            | (FinalDestinationState::Missing, _)
            | (FinalDestinationState::Unreadable(_), _) => true,
        };
        let interfered = self.source_interference_detected
            || self.pre_rename_edit_detected
            || final_interference_detected;
        PublicationReport {
            outcome: if interfered {
                PublicationOutcome::Interfered(self.operation)
            } else {
                self.clean_outcome
            },
            durability: if interfered {
                PublicationDurability::NotClaimedInterference
            } else {
                self.clean_durability
            },
            destination_mode: if interfered {
                DestinationModeStatus::NotClaimedInterference
            } else {
                self.clean_mode
            },
            temp_cleanup: self.temp_cleanup,
            source_interference_detected: self.source_interference_detected,
            pre_rename_edit_detected: self.pre_rename_edit_detected,
            final_interference_detected,
            final_state,
        }
    }
}

fn apply_destination_mode(
    file: &mut File,
    mode: u32,
    durability_errors: &mut Vec<String>,
) -> (DestinationModeStatus, Option<DocumentRead>) {
    if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(mode)) {
        return (DestinationModeStatus::Failed(error.to_string()), None);
    }
    if let Err(error) = file.sync_all() {
        durability_errors.push(format!("destination metadata fsync failed: {error}"));
    }
    match read_regular_bounded(file) {
        Ok(expected) if expected.preimage.mode == mode => {
            (DestinationModeStatus::Applied, Some(expected))
        }
        Ok(_) => (
            DestinationModeStatus::Failed("destination mode differs after application".into()),
            None,
        ),
        Err(error) => (DestinationModeStatus::Failed(error.to_string()), None),
    }
}

fn durability_status(errors: Vec<String>) -> PublicationDurability {
    if errors.is_empty() {
        PublicationDurability::Durable
    } else {
        PublicationDurability::Uncertain(errors.join("; "))
    }
}

fn openat(root: &File, name: &CStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<File> {
    // `mode_t` is u32 on Linux but u16 on macOS, and a variadic argument gets no implicit
    // promotion — widen explicitly so the one call compiles on both.
    let mode = libc::c_uint::from(mode);
    // SAFETY: `root` is an open directory fd, `name` is NUL-terminated, and ownership of a
    // successful returned fd is immediately transferred to `File`.
    let fd = unsafe { libc::openat(root.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `openat` returned this owned fd and no other `File` can own it.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn linkat(root: &File, old: &CStr, new: &CStr) -> io::Result<()> {
    // SAFETY: both names are NUL-terminated and interpreted relative to the held root fd.
    let result = unsafe {
        libc::linkat(
            root.as_raw_fd(),
            old.as_ptr(),
            root.as_raw_fd(),
            new.as_ptr(),
            0,
        )
    };
    cvt(result)
}

fn renameat(root: &File, old: &CStr, new: &CStr) -> io::Result<()> {
    // SAFETY: both names are NUL-terminated and interpreted relative to the held root fd.
    let result = unsafe {
        libc::renameat(
            root.as_raw_fd(),
            old.as_ptr(),
            root.as_raw_fd(),
            new.as_ptr(),
        )
    };
    cvt(result)
}

fn unlinkat(root: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: `name` is NUL-terminated and interpreted relative to the held root fd.
    cvt(unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) })
}

fn cvt(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The kernel refusing to open the named object AS A FILE — the swapped-special-file case
/// (a document path replaced by a symlink, fifo, socket, or device). Opening a unix socket
/// reports `ENXIO` on Linux but `EOPNOTSUPP` on macOS, so both spellings name the same refusal.
fn is_special_open_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ELOOP)
            | Some(libc::ENXIO)
            | Some(libc::ENODEV)
            | Some(libc::ENOTDIR)
            | Some(libc::EOPNOTSUPP)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn repo() -> TempDir {
        let repo = TempDir::new().unwrap();
        std::fs::create_dir(repo.path().join(".git")).unwrap();
        repo
    }

    fn present(outcome: ReadOutcome) -> DocumentRead {
        match outcome {
            ReadOutcome::Present(read) => read,
            ReadOutcome::Missing => panic!("document unexpectedly missing"),
        }
    }

    fn published_present(report: PublicationReport) -> DocumentRead {
        match report.final_state {
            FinalDestinationState::Present(read) => read,
            state => panic!("published destination is not readable: {state:?}"),
        }
    }

    #[test]
    fn nearest_normal_and_worktree_roots_are_physical() {
        let outer = repo();
        let inner = outer.path().join("nested/worktree");
        std::fs::create_dir_all(inner.join("deep")).unwrap();
        std::fs::write(inner.join(".git"), "gitdir: /tmp/example\n").unwrap();
        let store = DocumentStore::discover(&inner.join("deep")).unwrap();
        assert_eq!(store.root_path(), std::fs::canonicalize(&inner).unwrap());
        let metadata = std::fs::metadata(store.root_path()).unwrap();
        assert_eq!(
            store.root_identity(),
            DirectoryIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        );

        let plain = repo();
        std::fs::create_dir_all(plain.path().join("a/b")).unwrap();
        let store = DocumentStore::discover(&plain.path().join("a/b")).unwrap();
        assert_eq!(
            store.root_path(),
            std::fs::canonicalize(plain.path()).unwrap()
        );
    }

    #[test]
    fn discovery_resolves_a_symlinked_start_to_its_physical_root() {
        let parent = TempDir::new().unwrap();
        let physical = repo();
        std::fs::create_dir(physical.path().join("child")).unwrap();
        let link = parent.path().join("checkout-link");
        symlink(physical.path(), &link).unwrap();
        let store = DocumentStore::discover(&link.join("child")).unwrap();
        assert_eq!(
            store.root_path(),
            std::fs::canonicalize(physical.path()).unwrap()
        );
    }

    #[test]
    fn physical_root_substitution_between_discovery_and_open_is_refused() {
        let holder = TempDir::new().unwrap();
        // Discovery reports physical paths; macOS TMPDIR lives under a `/var -> /private/var`
        // symlink, so the fixture has to start from the resolved spelling to compare at all.
        let holder_path = std::fs::canonicalize(holder.path()).unwrap();
        let root = holder_path.join("repo");
        let moved = holder_path.join("original");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join(".git")).unwrap();
        let root_for_hook = root.clone();
        let result = DocumentStore::discover_with_test_hook(&root, move |candidate| {
            assert_eq!(candidate, root_for_hook);
            std::fs::rename(&root_for_hook, &moved).unwrap();
            std::fs::create_dir(&root_for_hook).unwrap();
            std::fs::create_dir(root_for_hook.join(".git")).unwrap();
        });
        assert!(matches!(result, Err(StoreError::RootSubstituted)));
    }

    #[test]
    fn ancestor_substitution_cannot_splice_the_held_start_into_another_checkout() {
        let holder = TempDir::new().unwrap();
        // See the note in `physical_root_substitution_…`: physical spellings only.
        let holder_path = std::fs::canonicalize(holder.path()).unwrap();
        let outer = holder_path.join("outer");
        let original_parent = outer.join("a");
        let start = original_parent.join("b");
        let attacker_parent = holder_path.join("attacker-parent");
        std::fs::create_dir_all(&start).unwrap();
        std::fs::create_dir(outer.join(".git")).unwrap();
        std::fs::create_dir(&attacker_parent).unwrap();
        std::fs::create_dir(attacker_parent.join(".git")).unwrap();
        let saved_parent = outer.join("saved-a");
        let start_for_hook = start.clone();
        let attacker_parent_for_hook = attacker_parent.clone();
        let result =
            DocumentStore::discover_with_ancestor_test_hook(&start, move |current_path, depth| {
                if depth == 0 {
                    assert_eq!(current_path, start_for_hook);
                    std::fs::rename(&original_parent, &saved_parent).unwrap();
                    std::fs::rename(&attacker_parent_for_hook, &original_parent).unwrap();
                }
            })
            .unwrap();
        assert_eq!(result.root_path(), outer);
        let metadata = std::fs::metadata(result.root_path()).unwrap();
        assert_eq!(
            result.root_identity(),
            DirectoryIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        );
    }

    #[test]
    fn substituted_reported_root_is_refused_even_when_the_original_root_fd_is_held() {
        let holder = TempDir::new().unwrap();
        let outer = holder.path().join("outer");
        let start = outer.join("a/b");
        let attacker = holder.path().join("attacker");
        let saved_outer = holder.path().join("saved-outer");
        std::fs::create_dir_all(&start).unwrap();
        std::fs::create_dir(outer.join(".git")).unwrap();
        std::fs::create_dir(&attacker).unwrap();
        std::fs::create_dir(attacker.join(".git")).unwrap();
        let outer_for_hook = outer.clone();
        let result = DocumentStore::discover_with_ancestor_test_hook(&start, move |_, depth| {
            if depth == 1 {
                std::fs::rename(&outer_for_hook, &saved_outer).unwrap();
                std::fs::rename(&attacker, &outer_for_hook).unwrap();
            }
        });
        assert!(matches!(result, Err(StoreError::RootSubstituted)));
    }

    #[test]
    fn an_error_opening_the_nearest_git_marker_never_falls_through_to_an_outer_repo() {
        let outer = repo();
        let inner = outer.path().join("inner");
        std::fs::create_dir(&inner).unwrap();
        symlink(outer.path().join(".git"), inner.join(".git")).unwrap();
        assert!(matches!(
            DocumentStore::discover(&inner),
            Err(StoreError::Io(_))
        ));
    }

    #[test]
    fn a_definitely_missing_inner_git_marker_falls_back_to_the_outer_repo() {
        let outer = repo();
        let inner = outer.path().join("inner/deep");
        std::fs::create_dir_all(&inner).unwrap();
        let store = DocumentStore::discover(&inner).unwrap();
        assert_eq!(
            store.root_path(),
            std::fs::canonicalize(outer.path()).unwrap()
        );
    }

    #[test]
    fn a_root_fd_never_falls_through_to_a_replacement_checkout() {
        let holder = TempDir::new().unwrap();
        let original = holder.path().join("repo");
        std::fs::create_dir(&original).unwrap();
        std::fs::create_dir(original.join(".git")).unwrap();
        std::fs::write(original.join("CERMET.md"), b"original").unwrap();
        let store = DocumentStore::discover(&original).unwrap();

        let moved = holder.path().join("moved");
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::create_dir(original.join(".git")).unwrap();
        std::fs::write(original.join("CERMET.md"), b"replacement-root").unwrap();
        assert_eq!(present(store.read().unwrap()).bytes, b"original");
    }

    #[test]
    fn missing_document_is_typed() {
        let repo = repo();
        let store = DocumentStore::discover(repo.path()).unwrap();
        assert_eq!(store.read().unwrap(), ReadOutcome::Missing);
    }

    #[test]
    fn reads_are_bounded_and_capture_exact_identity_and_digest() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        std::fs::write(&path, b"abc").unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let read = present(store.read().unwrap());
        assert_eq!(read.bytes, b"abc");
        assert_eq!(read.preimage.len, 3);
        assert_eq!(
            read.preimage.sha256,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        let meta = std::fs::metadata(path).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            (read.preimage.device, read.preimage.inode),
            (meta.dev(), meta.ino())
        );

        std::fs::write(
            repo.path().join("CERMET.md"),
            vec![b'x'; crate::cermet_document::MAX_DOCUMENT_BYTES + 1],
        )
        .unwrap();
        assert!(matches!(store.read(), Err(StoreError::InvalidFile)));

        std::fs::write(
            repo.path().join("CERMET.md"),
            vec![b'x'; crate::cermet_document::MAX_DOCUMENT_BYTES],
        )
        .unwrap();
        assert_eq!(
            present(store.read().unwrap()).bytes.len(),
            crate::cermet_document::MAX_DOCUMENT_BYTES
        );
    }

    #[test]
    fn short_eof_against_the_pre_read_length_is_refused() {
        let mut short = std::io::Cursor::new(b"abc");
        assert!(matches!(
            read_observed_length(&mut short, 4),
            Err(StoreError::PreimageChanged)
        ));
    }

    #[test]
    fn symlink_fifo_socket_and_device_are_refused_without_following_or_blocking() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        let outside = repo.path().join("outside");
        std::fs::write(&outside, b"do-not-read").unwrap();
        symlink(&outside, &path).unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        assert!(matches!(store.read(), Err(StoreError::InvalidFile)));
        std::fs::remove_file(&path).unwrap();

        let c_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        assert!(matches!(store.read(), Err(StoreError::InvalidFile)));
        assert!(started.elapsed() < Duration::from_secs(2));
        std::fs::remove_file(&path).unwrap();

        let listener = UnixListener::bind(&path).unwrap();
        assert!(matches!(store.read(), Err(StoreError::InvalidFile)));
        drop(listener);
        std::fs::remove_file(&path).unwrap();

        let mut device = File::open("/dev/null").unwrap();
        assert!(super::read_regular_bounded(&mut device).is_err());
    }

    #[test]
    fn no_clobber_create_is_durable_and_reports_the_final_read() {
        let repo = repo();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let report = store.create(b"new").unwrap();
        assert_eq!(report.outcome, PublicationOutcome::Created);
        assert_eq!(report.durability, PublicationDurability::Durable);
        assert_eq!(report.destination_mode, DestinationModeStatus::Applied);
        assert_eq!(report.temp_cleanup, TempCleanupStatus::Complete);
        let read = published_present(report);
        assert_eq!(read.bytes, b"new");
        assert_eq!(present(store.read().unwrap()), read);
        assert!(matches!(
            store.create(b"clobber"),
            Err(StoreError::AlreadyExists)
        ));
        assert_eq!(
            std::fs::read(repo.path().join("CERMET.md")).unwrap(),
            b"new"
        );
    }

    #[test]
    fn no_clobber_create_does_not_follow_an_existing_symlink() {
        let repo = repo();
        let outside = repo.path().join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, repo.path().join("CERMET.md")).unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        assert!(matches!(
            store.create(b"new"),
            Err(StoreError::AlreadyExists)
        ));
        assert_eq!(std::fs::read(outside).unwrap(), b"outside");
    }

    #[test]
    fn replacement_rechecks_inode_and_exact_bytes_before_rename() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        std::fs::write(&path, b"old").unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let first = present(store.read().unwrap());

        std::fs::write(&path, b"edited-in-place").unwrap();
        assert!(matches!(
            store.replace(&first.preimage, b"new"),
            Err(StoreError::PreimageChanged)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"edited-in-place");

        let current = present(store.read().unwrap());
        std::fs::rename(&path, repo.path().join("old-inode")).unwrap();
        std::fs::write(&path, &current.bytes).unwrap();
        assert!(matches!(
            store.replace(&current.preimage, b"new"),
            Err(StoreError::PreimageChanged)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), current.bytes);
    }

    #[test]
    fn edit_after_temp_fsync_is_caught_by_the_immediate_pre_rename_recheck() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        std::fs::write(&path, b"old").unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let first = present(store.read().unwrap());
        let result = store.replace_with_test_hooks(
            &first.preimage,
            b"intended",
            || std::fs::write(&path, b"concurrent-edit").unwrap(),
            || {},
            || store.root.sync_all(),
            || panic!("rename must not happen after the preimage changed"),
        );
        assert!(matches!(result, Err(StoreError::PreimageChanged)));
        assert_eq!(std::fs::read(path).unwrap(), b"concurrent-edit");
    }

    #[test]
    fn replacement_temp_stays_private_until_the_publication_boundary() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let first = present(store.read().unwrap());
        let report = store
            .replace_with_test_hooks(
                &first.preimage,
                b"intended",
                || {},
                || {
                    let temp = std::fs::read_dir(repo.path())
                        .unwrap()
                        .filter_map(Result::ok)
                        .find(|entry| {
                            entry
                                .file_name()
                                .to_string_lossy()
                                .starts_with(".cermet-document.")
                        })
                        .expect("named replacement temp");
                    assert_eq!(temp.metadata().unwrap().permissions().mode() & 0o777, 0o600);
                    assert_eq!(std::fs::read(temp.path()).unwrap(), b"intended");
                },
                || store.root.sync_all(),
                || {},
            )
            .unwrap();
        assert_eq!(report.destination_mode, DestinationModeStatus::Applied);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o666
        );
    }

    #[test]
    fn substituted_replace_temp_is_not_reported_as_the_intended_publication() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let first = present(store.read().unwrap());
        let report = store
            .replace_with_test_hooks(
                &first.preimage,
                b"intended",
                || {},
                || {
                    let temp = std::fs::read_dir(repo.path())
                        .unwrap()
                        .filter_map(Result::ok)
                        .find(|entry| {
                            entry
                                .file_name()
                                .to_string_lossy()
                                .starts_with(".cermet-document.")
                        })
                        .expect("named replacement temp")
                        .path();
                    std::fs::rename(&temp, repo.path().join("original-temp")).unwrap();
                    std::fs::write(&temp, b"attacker-bytes").unwrap();
                    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o666))
                        .unwrap();
                },
                || store.root.sync_all(),
                || {},
            )
            .unwrap();
        assert_eq!(
            report.outcome,
            PublicationOutcome::Interfered(PublicationOperation::Replace)
        );
        assert_eq!(
            report.destination_mode,
            DestinationModeStatus::NotClaimedInterference
        );
        assert_eq!(
            report.durability,
            PublicationDurability::NotClaimedInterference
        );
        assert!(report.source_interference_detected);
        assert!(report.final_interference_detected);
        let final_read = published_present(report);
        assert_eq!(final_read.bytes, b"attacker-bytes");
        assert_eq!(final_read.preimage.mode & 0o777, 0o666);
    }

    #[test]
    fn substituted_create_temp_reports_interference_and_the_actual_final_state() {
        let repo = repo();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let report = store
            .create_with_test_hooks(
                b"intended",
                |temp| {
                    let path = repo.path().join(temp.name.to_string_lossy().as_ref());
                    std::fs::rename(&path, repo.path().join("original-temp")).unwrap();
                    std::fs::write(&path, b"attacker-bytes").unwrap();
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
                },
                |temp| temp.unlink_if_same(),
                || store.root.sync_all(),
                |_, _| {},
                || {},
            )
            .unwrap();
        assert_eq!(
            report.outcome,
            PublicationOutcome::Interfered(PublicationOperation::Create)
        );
        assert_eq!(
            report.destination_mode,
            DestinationModeStatus::NotClaimedInterference
        );
        assert_eq!(
            report.durability,
            PublicationDurability::NotClaimedInterference
        );
        assert!(report.source_interference_detected);
        assert!(report.final_interference_detected);
        assert!(matches!(report.temp_cleanup, TempCleanupStatus::Failed(_)));
        let final_read = published_present(report);
        assert_eq!(final_read.bytes, b"attacker-bytes");
        assert_eq!(final_read.preimage.mode & 0o777, 0o666);
    }

    #[test]
    fn a_writer_winning_after_destination_binding_suppresses_clean_publication_claims() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        std::fs::write(&path, b"old").unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let first = present(store.read().unwrap());
        let report = store
            .replace_with_test_hooks(
                &first.preimage,
                b"intended",
                || {},
                || {},
                || store.root.sync_all(),
                || {
                    std::fs::remove_file(&path).unwrap();
                    std::fs::write(&path, b"post-bind-winner").unwrap();
                },
            )
            .unwrap();
        assert_eq!(
            report.outcome,
            PublicationOutcome::Interfered(PublicationOperation::Replace)
        );
        assert_eq!(
            report.destination_mode,
            DestinationModeStatus::NotClaimedInterference
        );
        assert_eq!(
            report.durability,
            PublicationDurability::NotClaimedInterference
        );
        assert!(!report.source_interference_detected);
        assert!(report.final_interference_detected);
        assert_eq!(published_present(report).bytes, b"post-bind-winner");
    }

    #[test]
    fn same_inode_chmod_after_metadata_sync_suppresses_clean_publication_claims() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        let store = DocumentStore::discover(repo.path()).unwrap();
        let published_inode = std::cell::Cell::new(0);
        let report = store
            .create_with_test_hooks(
                b"intended",
                |_| {},
                |temp| temp.unlink_if_same(),
                || store.root.sync_all(),
                |_, _| {},
                || {
                    let metadata = std::fs::metadata(&path).unwrap();
                    published_inode.set(metadata.ino());
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                },
            )
            .unwrap();
        assert_eq!(
            report.outcome,
            PublicationOutcome::Interfered(PublicationOperation::Create)
        );
        assert_eq!(
            report.destination_mode,
            DestinationModeStatus::NotClaimedInterference
        );
        assert_eq!(
            report.durability,
            PublicationDurability::NotClaimedInterference
        );
        let final_read = published_present(report);
        assert_eq!(final_read.preimage.inode, published_inode.get());
        assert_eq!(final_read.preimage.mode & 0o777, 0o600);
        assert_eq!(final_read.bytes, b"intended");
    }

    #[test]
    fn same_inode_identical_rewrite_after_metadata_sync_suppresses_clean_publication_claims() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        std::fs::write(&path, b"old").unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let first = present(store.read().unwrap());
        let published_inode = std::cell::Cell::new(0);
        let report = store
            .replace_with_test_hooks(
                &first.preimage,
                b"intended",
                || {},
                || {},
                || store.root.sync_all(),
                || {
                    let metadata = std::fs::metadata(&path).unwrap();
                    published_inode.set(metadata.ino());
                    let before = metadata_change_cookie(&metadata);
                    let mut after = before;
                    for _ in 0..16 {
                        std::fs::write(&path, b"intended").unwrap();
                        File::open(&path).unwrap().sync_all().unwrap();
                        after = metadata_change_cookie(&std::fs::metadata(&path).unwrap());
                        if after != before {
                            break;
                        }
                    }
                    assert_ne!(after, before, "rewrite must advance the metadata cookie");
                },
            )
            .unwrap();
        assert_eq!(
            report.outcome,
            PublicationOutcome::Interfered(PublicationOperation::Replace)
        );
        assert_eq!(
            report.destination_mode,
            DestinationModeStatus::NotClaimedInterference
        );
        assert_eq!(
            report.durability,
            PublicationDurability::NotClaimedInterference
        );
        let final_read = published_present(report);
        assert_eq!(final_read.preimage.inode, published_inode.get());
        assert_eq!(final_read.bytes, b"intended");
    }

    #[test]
    fn normal_replace_preserves_permissions_and_cleans_its_exclusive_temp() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let first = present(store.read().unwrap());
        let report = store.replace(&first.preimage, b"new").unwrap();
        assert_eq!(report.outcome, PublicationOutcome::Replaced);
        assert_eq!(report.durability, PublicationDurability::Durable);
        assert!(!report.pre_rename_edit_detected);
        let final_read = published_present(report);
        assert_eq!(final_read.bytes, b"new");
        assert_ne!(final_read.preimage.inode, first.preimage.inode);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let leftovers = std::fs::read_dir(repo.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".cermet-document.")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn replacement_refuses_a_special_file_swapped_after_read() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        std::fs::write(&path, b"old").unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let first = present(store.read().unwrap());
        std::fs::remove_file(&path).unwrap();
        let _listener = UnixListener::bind(&path).unwrap();
        assert!(matches!(
            store.replace(&first.preimage, b"new"),
            Err(StoreError::InvalidFile)
        ));
    }

    #[test]
    fn a_hostile_edit_completed_in_the_final_rename_window_is_not_treated_as_aligned() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        std::fs::write(&path, b"old").unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let first = present(store.read().unwrap());
        let report = store
            .replace_with_test_hooks(
                &first.preimage,
                b"intended",
                || {},
                || std::fs::write(&path, b"hostile-window-edit").unwrap(),
                || store.root.sync_all(),
                || {},
            )
            .unwrap();
        assert!(report.pre_rename_edit_detected);
        assert_eq!(
            report.outcome,
            PublicationOutcome::Interfered(PublicationOperation::Replace)
        );
        assert_eq!(published_present(report).bytes, b"intended");
    }

    #[test]
    fn create_reports_final_state_when_cleanup_and_directory_fsync_fail_after_publication() {
        let repo = repo();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let report = store
            .create_with_test_hooks(
                b"published",
                |_| {},
                |_| Err(io::Error::other("injected cleanup failure")),
                || Err(io::Error::other("injected directory fsync failure")),
                |file, temp| {
                    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
                    assert_eq!(
                        std::fs::metadata(repo.path().join("CERMET.md"))
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o777,
                        0o600
                    );
                    assert_eq!(
                        std::fs::read(repo.path().join(temp.name.to_string_lossy().as_ref()))
                            .unwrap(),
                        b"published"
                    );
                },
                || {},
            )
            .unwrap();
        assert_eq!(report.outcome, PublicationOutcome::Created);
        assert!(matches!(
            report.temp_cleanup,
            TempCleanupStatus::Failed(ref error) if error.contains("injected cleanup failure")
        ));
        assert!(matches!(
            report.durability,
            PublicationDurability::Uncertain(ref error) if error.contains("injected directory fsync failure")
        ));
        assert_eq!(published_present(report).bytes, b"published");
    }

    #[test]
    fn replace_reports_final_state_when_directory_fsync_fails_after_publication() {
        let repo = repo();
        let path = repo.path().join("CERMET.md");
        std::fs::write(&path, b"old").unwrap();
        let store = DocumentStore::discover(repo.path()).unwrap();
        let first = present(store.read().unwrap());
        let report = store
            .replace_with_test_hooks(
                &first.preimage,
                b"published",
                || {},
                || {},
                || Err(io::Error::other("injected directory fsync failure")),
                || {},
            )
            .unwrap();
        assert_eq!(report.outcome, PublicationOutcome::Replaced);
        assert!(matches!(
            report.durability,
            PublicationDurability::Uncertain(ref error) if error.contains("injected directory fsync failure")
        ));
        assert_eq!(published_present(report).bytes, b"published");
    }
}
