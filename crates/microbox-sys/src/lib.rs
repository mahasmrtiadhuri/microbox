//! Single-threaded Linux setup primitives. Never call isolation functions on runtime workers.
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Milestone 1 supports Linux x86-64 only");
use serde::{Deserialize, Serialize};
use std::{ffi::CString, io, path::Path};
pub mod seccomp;
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyMode {
    Kill,
    Errno,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    pub rootfs: String,
    pub cgroup: String,
    pub argv: Vec<String>,
    pub tmp_bytes: u64,
    pub mode: DenyMode,
}
fn checked(rc: i32) -> io::Result<()> {
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn c(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"))
}
fn mount(
    src: Option<&str>,
    target: &str,
    kind: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let src = src.map(c).transpose()?;
    let target = c(target)?;
    let kind = kind.map(c).transpose()?;
    let data = data.map(c).transpose()?;
    // SAFETY: CString buffers outlive the synchronous mount syscall; null means absent option.
    checked(unsafe {
        libc::mount(
            src.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            kind.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        )
    })
}
pub fn cgroup2(path: &Path) -> io::Result<bool> {
    let p = c(path
        .to_str()
        .ok_or_else(|| io::Error::other("non UTF-8 path"))?)?;
    let mut s = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: writable output pointer has the correct statfs layout; initialized only on success.
    checked(unsafe { libc::statfs(p.as_ptr(), s.as_mut_ptr()) })?;
    Ok(unsafe { s.assume_init() }.f_type == libc::CGROUP2_SUPER_MAGIC)
}
pub fn root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}
pub fn unshare() -> io::Result<()> {
    // SAFETY: helper is a dedicated single-threaded process, with no runtime thread pool.
    checked(unsafe {
        libc::unshare(
            libc::CLONE_NEWNS
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUTS,
        )
    })
}
pub fn filesystem(s: &Setup) -> io::Result<()> {
    // Input rootfs and mountpoint ownership are validated by the trusted supervisor.
    mount(None, "/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    mount(Some(&s.rootfs), &s.rootfs, None, libc::MS_BIND, None)?; // Non-recursive: never import submounts.
    std::env::set_current_dir(&s.rootfs)?;
    let dot = c(".")?;
    let old = c(".microbox-old")?;
    // SAFETY: valid C strings; old root is a prepared directory inside new root.
    checked(unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), old.as_ptr()) } as i32)?;
    std::env::set_current_dir("/")?;
    let old = c("/.microbox-old")?;
    checked(unsafe { libc::umount2(old.as_ptr(), libc::MNT_DETACH) })?;
    mount(
        None,
        "/",
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    )?;
    mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some(&format!("size={},nr_inodes=4096,mode=1777", s.tmp_bytes)),
    )?;
    for p in ["/dev", "/sys"] {
        mount(
            Some("tmpfs"),
            p,
            Some("tmpfs"),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some("size=4096,mode=0555"),
        )?;
    }
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("hidepid=2"),
    )?;
    Ok(())
}
pub fn drop_privileges() -> io::Result<()> {
    // SAFETY: only the single-threaded payload child changes identity; no shared credential state.
    checked(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
    checked(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    })?;
    for resource in [libc::RLIMIT_CORE, libc::RLIMIT_MEMLOCK] {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        checked(unsafe { libc::setrlimit(resource, &limit) })?;
    }
    let files = libc::rlimit {
        rlim_cur: 256,
        rlim_max: 256,
    };
    checked(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &files) })?;
    for cap in 0..64 {
        let r = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if r == -1 && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
            return Err(io::Error::last_os_error());
        }
    }
    checked(unsafe { libc::setgroups(0, std::ptr::null()) })?;
    checked(unsafe { libc::setresgid(65534, 65534, 65534) })?;
    checked(unsafe { libc::setresuid(65534, 65534, 65534) })?;
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let data = [
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: Linux capability ABI v3 requires exactly two repr(C) data words.
    checked(unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } as i32)?;
    checked(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })?;
    Ok(())
}
