//! Trusted setup helper. Not setuid; launch only from an already privileged supervisor.
use anyhow::{bail, Context, Result};
use microbox_sys::{self as sys, Setup};
use std::{
    ffi::CString,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::net::UnixStream,
};
fn record(s: &mut UnixStream, v: serde_json::Value) -> Result<()> {
    let mut b = serde_json::to_vec(&v)?;
    b.push(b'\n');
    s.write_all(&b)?;
    Ok(())
}
fn fork() -> Result<libc::pid_t> {
    let p = unsafe { libc::fork() };
    if p < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(p)
    }
}
fn wait(pid: libc::pid_t) -> Result<i32> {
    loop {
        let mut status = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return Ok(status);
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(std::io::Error::last_os_error().into());
        }
    }
}
fn payload(s: &Setup, status: &mut UnixStream) -> Result<()> {
    sys::filesystem(s).context("mount isolation")?;
    // The forked namespace init is PID 1 and remains trusted. It reaps all orphaned descendants.
    if unsafe { libc::getpid() } != 1 {
        bail!("PID namespace entry failed")
    }
    let argv: Vec<CString> = s
        .argv
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<std::result::Result<_, _>>()?;
    let mut args: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    args.push(std::ptr::null());
    let env = [CString::new("PATH=/bin:/usr/bin")?, CString::new("LANG=C")?];
    let envp = [env[0].as_ptr(), env[1].as_ptr(), std::ptr::null()];
    let mut filter = sys::seccomp::compile(s.mode);
    let mut errpipe = [0; 2];
    if unsafe { libc::pipe2(errpipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let child = fork()?;
    if child == 0 {
        // SAFETY: this code runs only in a single-threaded dedicated helper, not after fork in Tokio.
        unsafe {
            libc::close(errpipe[0]);
        }
        let mut did_ready = false;
        let result = (|| -> Result<()> {
            sys::drop_privileges()?;
            sys::seccomp::install(&mut filter)?;
            record(status, serde_json::json!({"kind":"ready"}))?;
            did_ready = true;
            unsafe {
                libc::close(status.as_raw_fd());
            }
            unsafe {
                libc::execve(argv[0].as_ptr(), args.as_ptr(), envp.as_ptr());
            }
            Err(std::io::Error::last_os_error().into())
        })();
        if result.is_err() {
            let err = [if did_ready { 2u8 } else { 1u8 }];
            unsafe {
                libc::write(errpipe[1], err.as_ptr().cast(), 1);
                libc::_exit(126);
            }
        }
        unreachable!()
    }
    unsafe {
        libc::close(errpipe[1]);
    }
    let mut err = unsafe { std::fs::File::from_raw_fd(errpipe[0]) };
    let mut b = Vec::new();
    err.read_to_end(&mut b)?;
    drop(err);
    if !b.is_empty() {
        record(
            status,
            serde_json::json!({"kind":if b[0]==1{"setup_failed"}else{"launch_failed"}}),
        )?;
    }
    let main_status = loop {
        let mut st = 0;
        let p = unsafe { libc::waitpid(-1, &mut st, 0) };
        if p == child {
            break st;
        }
        if p < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            bail!("init waitpid failed")
        }
    };
    record(
        status,
        serde_json::json!({"kind":"exit","code":if libc::WIFEXITED(main_status){Some(libc::WEXITSTATUS(main_status))}else{None},"signal":if libc::WIFSIGNALED(main_status){Some(libc::WTERMSIG(main_status))}else{None}}),
    )?;
    Ok(())
}
fn run(status: &mut UnixStream) -> Result<()> {
    if !sys::root() {
        bail!("helper requires an explicitly privileged caller")
    }
    let mut input = String::new();
    std::io::stdin().take(65537).read_to_string(&mut input)?;
    if input.len() > 65536 {
        bail!("configuration too large")
    }
    let s: Setup = serde_json::from_str(&input)?;
    if s.argv.is_empty() || !s.argv[0].starts_with('/') {
        bail!("absolute payload path required")
    }
    // No configuration FD or other host file reference survives into the payload.
    let n = std::fs::File::open("/dev/null")?;
    if unsafe { libc::dup2(n.as_raw_fd(), 0) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    drop(n);
    if unsafe { libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::fcntl(status.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    std::fs::write(
        format!("{}/cgroup.procs", s.cgroup),
        std::process::id().to_string(),
    )?;
    sys::unshare()?;
    let p = fork()?;
    if p == 0 {
        let r = payload(&s, status);
        if let Err(e) = r {
            let _ = record(
                status,
                serde_json::json!({"kind":"setup_failed","message":e.to_string()}),
            );
            unsafe {
                libc::_exit(125);
            }
        }
        unsafe {
            libc::_exit(0);
        }
    }
    let st = wait(p)?;
    if !libc::WIFEXITED(st) || libc::WEXITSTATUS(st) != 0 {
        bail!("namespace init exited abnormally")
    }
    Ok(())
}
fn main() {
    // SAFETY: descriptor 3 is an inherited private control socket provisioned by the supervisor.
    let mut status = unsafe { UnixStream::from_raw_fd(3) };
    if let Err(e) = run(&mut status) {
        let _ = record(
            &mut status,
            serde_json::json!({"kind":"setup_failed","message":e.to_string()}),
        );
        std::process::exit(125)
    }
}
