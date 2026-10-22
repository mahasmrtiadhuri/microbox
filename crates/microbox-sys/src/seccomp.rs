//! Classic BPF allowlist. Unknown ABI kills even when the syscall-denial mode is errno.
use crate::DenyMode;
use std::io;
const LD: u16 = 0x20;
const JEQ: u16 = 0x15;
const JSET: u16 = 0x45;
const RET: u16 = 0x06;
const ALLOW: u32 = 0x7fff0000;
const KILL: u32 = 0x80000000;
const ERRNO: u32 = 0x00050000;
fn ins(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
pub fn compile(mode: DenyMode) -> Vec<libc::sock_filter> {
    let deny = match mode {
        DenyMode::Kill => KILL,
        DenyMode::Errno => ERRNO | libc::EPERM as u32,
    };
    let mut p = vec![
        ins(LD, 0, 0, 4),
        ins(JEQ, 1, 0, 0xc000003e),
        ins(RET, 0, 0, KILL),
        ins(LD, 0, 0, 0),
        ins(JSET, 0, 1, 0x40000000),
        ins(RET, 0, 0, KILL),
    ];
    // clone3's pointer argument cannot be inspected safely with classic BPF. ENOSYS enables libc fallback.
    p.extend([
        ins(JEQ, 0, 1, libc::SYS_clone3 as u32),
        ins(RET, 0, 0, ERRNO | libc::ENOSYS as u32),
    ]);
    // clone: only ordinary process/thread creation flags; reject namespace and parent-changing flags.
    let safe = libc::CLONE_VM
        | libc::CLONE_FS
        | libc::CLONE_FILES
        | libc::CLONE_SIGHAND
        | libc::CLONE_THREAD
        | libc::CLONE_SYSVSEM
        | libc::CLONE_SETTLS
        | libc::CLONE_PARENT_SETTID
        | libc::CLONE_CHILD_CLEARTID
        | libc::CLONE_CHILD_SETTID
        | 0xff;
    p.extend([
        ins(JEQ, 0, 7, libc::SYS_clone as u32),
        ins(LD, 0, 0, 20),
        ins(JEQ, 1, 0, 0),
        ins(RET, 0, 0, deny),
        ins(LD, 0, 0, 16),
        ins(JSET, 0, 1, !(safe as u32)),
        ins(RET, 0, 0, deny),
        ins(RET, 0, 0, ALLOW),
    ]);
    // Reload nr: the clone block changes the accumulator only on the clone branch, which returns.
    let allow = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_ioctl,
        libc::SYS_access,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_getdents64,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_fcntl,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_pipe,
        libc::SYS_pipe2,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_select,
        libc::SYS_pselect6,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_eventfd2,
        libc::SYS_futex,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_arch_prctl,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_getgroups,
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_getrlimit,
        libc::SYS_prlimit64,
        libc::SYS_getrusage,
        libc::SYS_times,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_execve,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_kill,
        libc::SYS_tgkill,
        libc::SYS_pause,
        libc::SYS_rt_sigsuspend,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept4,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_shutdown,
        libc::SYS_mkdir,
        libc::SYS_mkdirat,
        libc::SYS_unlink,
        libc::SYS_unlinkat,
        libc::SYS_rename,
        libc::SYS_renameat,
        libc::SYS_ftruncate,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
    ];
    for nr in allow {
        p.extend([ins(JEQ, 0, 1, nr as u32), ins(RET, 0, 0, ALLOW)]);
    }
    p.push(ins(RET, 0, 0, deny));
    p
}
pub fn install(p: &mut [libc::sock_filter]) -> io::Result<()> {
    let prog = libc::sock_fprog {
        len: p.len() as u16,
        filter: p.as_mut_ptr(),
    };
    // SAFETY: the kernel copies the validated program synchronously; no pointer survives this call.
    let r = unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &prog) };
    if r == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn run(p: &[libc::sock_filter], nr: u32, arch: u32, arg: u64) -> u32 {
        let data = [nr, 0, arch, 0, arg as u32, (arg >> 32) as u32];
        let (mut pc, mut a) = (0, 0);
        loop {
            let i = &p[pc];
            pc += 1;
            match i.code {
                LD => {
                    a = match i.k {
                        0 => data[0],
                        4 => data[2],
                        16 => data[4],
                        20 => data[5],
                        _ => panic!("offset"),
                    }
                }
                JEQ => pc += if a == i.k { i.jt } else { i.jf } as usize,
                JSET => pc += if a & i.k != 0 { i.jt } else { i.jf } as usize,
                RET => return i.k,
                _ => panic!("instruction"),
            }
        }
    }
    #[test]
    fn native_read_allowed() {
        assert_eq!(
            run(
                &compile(DenyMode::Kill),
                libc::SYS_read as u32,
                0xc000003e,
                0
            ),
            ALLOW
        );
    }
    #[test]
    fn unknown_abi_and_x32_die() {
        for mode in [DenyMode::Kill, DenyMode::Errno] {
            let p = compile(mode);
            assert_eq!(run(&p, 0, 0x40000003, 0), KILL);
            assert_eq!(run(&p, 0x40000000, 0xc000003e, 0), KILL);
        }
    }
    #[test]
    fn privileged_operations_denied() {
        for nr in [
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_unshare,
            libc::SYS_mount,
            libc::SYS_setns,
            libc::SYS_keyctl,
            libc::SYS_io_uring_setup,
        ] {
            assert_eq!(
                run(&compile(DenyMode::Kill), nr as u32, 0xc000003e, 0),
                KILL
            );
            assert_eq!(
                run(&compile(DenyMode::Errno), nr as u32, 0xc000003e, 0),
                ERRNO | 1
            );
        }
    }
    #[test]
    fn clone_flags_checked() {
        let p = compile(DenyMode::Kill);
        assert_eq!(
            run(&p, libc::SYS_clone as u32, 0xc000003e, libc::SIGCHLD as u64),
            ALLOW
        );
        for flags in [
            libc::CLONE_NEWUSER as u64,
            libc::CLONE_NEWNET as u64,
            libc::CLONE_PARENT as u64,
            1u64 << 40,
        ] {
            assert_eq!(run(&p, libc::SYS_clone as u32, 0xc000003e, flags), KILL);
        }
    }
    #[test]
    fn clone3_fails_closed_with_fallback() {
        assert_eq!(
            run(
                &compile(DenyMode::Kill),
                libc::SYS_clone3 as u32,
                0xc000003e,
                0
            ),
            ERRNO | libc::ENOSYS as u32
        );
    }
}
