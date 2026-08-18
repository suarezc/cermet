//! Group-database lookups (`getgrnam_r` / `getgrgid_r`).
//!
//! Why this exists rather than `nix::unistd::Group`: nix reads the `char **gr_mem` member array
//! with an ALIGNED dereference, but macOS's `getgr*_r` packs that array at an arbitrary byte
//! offset inside the caller's buffer (offset 0x13 on this box). That read is undefined behavior
//! and aborts outright under the debug alignment check, so every group lookup on macOS — the
//! startup `cermet-approvers` / `cermet-agents` resolution and doctor's membership check — went
//! through a broken path. Reading the array unaligned is the only difference from nix's version.

use std::ffi::{CStr, CString};
use std::io;
use std::ptr;

const INITIAL_BUFFER: usize = 4096;
const MAX_BUFFER: usize = 1 << 20;

/// One group record: everything the daemon asks the group database for.
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    /// Supplementary members — the usernames in the group's member list.
    pub members: Vec<String>,
}

/// Look a group up by NAME. `Ok(None)` means the group does not exist.
pub fn by_name(name: &str) -> io::Result<Option<GroupEntry>> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "group name contains a NUL"))?;
    lookup(|grp, buf, cap, res| unsafe { libc::getgrnam_r(name.as_ptr(), grp, buf, cap, res) })
}

/// Look a group up by GID. `Ok(None)` means the gid names no group.
pub fn by_gid(gid: u32) -> io::Result<Option<GroupEntry>> {
    lookup(|grp, buf, cap, res| unsafe { libc::getgrgid_r(gid, grp, buf, cap, res) })
}

fn lookup<F>(call: F) -> io::Result<Option<GroupEntry>>
where
    F: Fn(*mut libc::group, *mut libc::c_char, usize, *mut *mut libc::group) -> libc::c_int,
{
    let mut capacity = INITIAL_BUFFER;
    loop {
        let mut buffer = vec![0 as libc::c_char; capacity];
        let mut record = std::mem::MaybeUninit::<libc::group>::uninit();
        let mut found: *mut libc::group = ptr::null_mut();
        let code = call(
            record.as_mut_ptr(),
            buffer.as_mut_ptr(),
            capacity,
            &mut found,
        );
        // POSIX returns the errno; some libcs return -1 and set errno instead.
        let errno = if code < 0 {
            io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            code
        };
        if errno == libc::ERANGE && capacity < MAX_BUFFER {
            capacity *= 2;
            continue;
        }
        if errno != 0 {
            return Err(io::Error::from_raw_os_error(errno));
        }
        if found.is_null() {
            return Ok(None);
        }
        // SAFETY: a zero return with a non-null result pointer means the record is initialized.
        let record = unsafe { record.assume_init() };
        return Ok(Some(GroupEntry {
            // SAFETY: `gr_name` points into `buffer`, which outlives this read.
            name: unsafe { CStr::from_ptr(record.gr_name) }
                .to_string_lossy()
                .into_owned(),
            gid: record.gr_gid,
            // SAFETY: `gr_mem` is a NULL-terminated array of C strings living in `buffer`, which
            // outlives this read. Unaligned because macOS packs it (see the module note).
            members: unsafe { members(record.gr_mem) },
        }));
    }
}

unsafe fn members(mem: *mut *mut libc::c_char) -> Vec<String> {
    let mut names = Vec::new();
    if mem.is_null() {
        return names;
    }
    for index in 0.. {
        let entry = ptr::read_unaligned(mem.offset(index));
        if entry.is_null() {
            break;
        }
        names.push(CStr::from_ptr(entry).to_string_lossy().into_owned());
    }
    names
}

#[cfg(test)]
mod tests {
    /// The read that aborts under nix on macOS: resolve the running process's own primary group
    /// and walk its member list. Nothing about the CONTENTS is asserted — the point is that the
    /// walk completes on both platforms.
    #[test]
    fn a_real_groups_member_list_is_readable() {
        let gid = nix::unistd::getgid().as_raw();
        let entry = super::by_gid(gid)
            .expect("the running process's own gid resolves")
            .expect("the running process's own gid names a group");
        assert_eq!(entry.gid, gid);
        assert!(entry.members.iter().all(|m| !m.is_empty()));
    }

    #[test]
    fn an_absent_group_is_none_not_an_error() {
        assert!(super::by_name("cermet-no-such-group-exists")
            .expect("an absent name is not an error")
            .is_none());
    }
}
