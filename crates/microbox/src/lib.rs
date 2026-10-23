//! Experimental privileged Linux sandbox supervisor. See SECURITY.md before use.
#![forbid(unsafe_op_in_unsafe_fn)]
pub mod audit;
mod cgroup;
use anyhow::{bail, Context, Result};
pub use microbox_sys::{DenyMode, Network};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        net::UnixStream,
        process::CommandExt,
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
#[derive(Debug)]
pub enum InitializationError {
    MissingCgroupV2,
    MissingCgroupKillSupport,
    MissingController(String),
    RequiresPrivilegedHost,
    InvalidRootfs(String),
}
impl std::fmt::Display for InitializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for InitializationError {}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub rootfs: PathBuf,
    pub helper: PathBuf,
    pub cgroup_parent: PathBuf,
    pub audit_path: PathBuf,
    pub argv: Vec<String>,
    pub memory_bytes: u64,
    pub tmp_bytes: u64,
    pub pids: u32,
    pub cpu_quota_us: u32,
    pub timeout_ms: u64,
    pub output_limit_bytes: usize,
    pub deny_mode: DenyMode,
    #[serde(default)]
    pub network: Network,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if !microbox_sys::root() {
            return Err(InitializationError::RequiresPrivilegedHost.into());
        }
        if self.argv.is_empty()
            || !self.argv[0].starts_with('/')
            || self.argv.iter().any(|x| x.as_bytes().contains(&0))
        {
            bail!("nonempty absolute command and NUL-free argv required")
        }
        if self.memory_bytes < 16 * 1024 * 1024
            || self.tmp_bytes == 0
            || self.tmp_bytes > self.memory_bytes
            || self.pids < 4
            || self.pids > 4096
            || self.cpu_quota_us < 1000
            || self.cpu_quota_us > 100000
            || self.timeout_ms == 0
            || self.timeout_ms > 3600000
            || self.output_limit_bytes == 0
            || self.output_limit_bytes > 16 * 1024 * 1024
        {
            bail!("invalid resource bounds")
        }
        let root = self.rootfs.canonicalize()?;
        if root == std::path::Path::new("/") || root != self.rootfs {
            bail!("rootfs must be canonical and cannot be the host root")
        }
        for rel in ["", "tmp", "proc", "dev", "sys", ".microbox-old"] {
            let p = root.join(rel);
            let m = std::fs::symlink_metadata(&p)?;
            if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(InitializationError::InvalidRootfs(p.display().to_string()).into());
            }
        }
        if std::fs::read_dir(root.join(".microbox-old"))?
            .next()
            .is_some()
        {
            bail!("old-root directory must be empty")
        }
        let helper = self.helper.canonicalize()?;
        if helper != self.helper {
            bail!("helper must use its canonical absolute path")
        }
        let m = std::fs::metadata(helper)?;
        if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            bail!("helper must be root-owned and not group/world writable")
        }
        if !self.cgroup_parent.is_absolute()
            || self.cgroup_parent.canonicalize()? != self.cgroup_parent
        {
            bail!("canonical cgroup delegation path required")
        }
        if let Network::HttpsFetch { socket } = &self.network {
            let socket_path = PathBuf::from(socket);
            if !socket_path.is_absolute() || socket_path.canonicalize()? != socket_path {
                bail!("canonical proxy socket path required")
            }
            let m = std::fs::symlink_metadata(&socket_path)?;
            let parent = std::fs::symlink_metadata(socket_path.parent().context("socket parent")?)?;
            if !m.file_type().is_socket()
                || ![0, 65533].contains(&m.uid())
                || !parent.is_dir()
                || ![0, 65533].contains(&parent.uid())
                || parent.mode() & 0o077 != 0
            {
                bail!("proxy socket requires a trusted private host directory and dedicated proxy owner")
            }
            for rel in [".microbox-egress", ".microbox-egress/fetch.sock"] {
                let m = std::fs::symlink_metadata(root.join(rel))?;
                if m.uid() != 0
                    || m.mode() & 0o022 != 0
                    || m.file_type().is_symlink()
                    || (rel.ends_with("fetch.sock") && (!m.is_file() || m.len() != 0))
                    || (!rel.ends_with("fetch.sock") && !m.is_dir())
                {
                    bail!("invalid reserved rootfs proxy mountpoint")
                }
            }
        }
        Ok(())
    }
}
impl Config {
    pub fn new(
        rootfs: PathBuf,
        helper: PathBuf,
        cgroup_parent: PathBuf,
        audit_path: PathBuf,
        argv: Vec<String>,
    ) -> Self {
        Self {
            rootfs,
            helper,
            cgroup_parent,
            audit_path,
            argv,
            memory_bytes: 128 * 1024 * 1024,
            tmp_bytes: 16 * 1024 * 1024,
            pids: 64,
            cpu_quota_us: 50000,
            timeout_ms: 5000,
            output_limit_bytes: 65536,
            deny_mode: DenyMode::Kill,
            network: Network::Airgap,
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Capture {
    pub bytes: u64,
    pub sha256: String,
    pub prefix_hex: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Outcome {
    pub version: u32,
    pub run_id: String,
    pub termination: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub setup_ready: bool,
    pub cleanup_complete: bool,
    pub timings_us: serde_json::Value,
    pub resources: serde_json::Value,
    pub stdout: Capture,
    pub stderr: Capture,
    pub audit_root: String,
}
fn capture<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    exceeded: Arc<AtomicBool>,
) -> std::thread::JoinHandle<Result<Capture>> {
    std::thread::spawn(move || {
        let mut hash = Sha256::new();
        let mut prefix = Vec::new();
        let mut total = 0u64;
        let mut b = [0u8; 8192];
        loop {
            let n = reader.read(&mut b)?;
            if n == 0 {
                break;
            }
            hash.update(&b[..n]);
            total = total.saturating_add(n as u64);
            let keep = n.min(limit.saturating_sub(prefix.len()));
            prefix.extend_from_slice(&b[..keep]);
            if total > limit as u64 {
                exceeded.store(true, Ordering::Release)
            }
        }
        Ok(Capture {
            bytes: total,
            sha256: hex::encode(hash.finalize()),
            prefix_hex: hex::encode(prefix),
        })
    })
}
struct ChildGuard(Option<Child>);
impl std::ops::Deref for ChildGuard {
    type Target = Child;
    fn deref(&self) -> &Child {
        self.0.as_ref().unwrap()
    }
}
impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Child {
        self.0.as_mut().unwrap()
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            let _ = child.kill();
            // Never block an error return indefinitely on an uninterruptible task.
            let _ = std::thread::Builder::new()
                .name("microbox-reaper".into())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
    }
}
/// Dropping this future requests cancellation. A dedicated supervisor thread still performs teardown.
/// Await completion for a final audit root; a cancelled caller can inspect its exclusive audit file.
pub async fn run(config: Config) -> Result<Outcome> {
    let (send, receive) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("microbox-supervisor".into())
        .spawn(move || {
            let result = supervise(config, &send);
            let _ = send.send(result);
        })?;
    receive.await.context("supervisor thread terminated")?
}
fn supervise(
    config: Config,
    cancel: &tokio::sync::oneshot::Sender<Result<Outcome>>,
) -> Result<Outcome> {
    let start = Instant::now();
    config.validate()?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&config.audit_path)
        .context("exclusive audit creation")?;
    let mut chain = audit::Chain::new(file);
    chain.append(serde_json::json!({"kind":"configuration","config":config}))?;
    let mut group = cgroup::Group::create(&config)?;
    let run_id = group
        .path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let setup = microbox_sys::Setup {
        rootfs: config.rootfs.to_string_lossy().into_owned(),
        cgroup: group.path.to_string_lossy().into_owned(),
        argv: config.argv.clone(),
        tmp_bytes: config.tmp_bytes,
        mode: config.deny_mode,
        network: config.network.clone(),
    };
    let input = serde_json::to_vec(&setup)?;
    if input.len() > 65536 {
        bail!("helper configuration exceeds 64 KiB")
    }
    let (read, write) = UnixStream::pair()?;
    // Duplicate high so fd 3 cannot collide with a temporary Command stdio descriptor.
    let high = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if high < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let handoff = unsafe { std::fs::File::from_raw_fd(high) };
    drop(write);
    let mut cmd = Command::new(&config.helper);
    cmd.env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: pre_exec performs only async-signal-safe dup2. All allocation/setup happens after helper exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(high, 3) < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = ChildGuard(Some(cmd.spawn().context("launch setup helper")?));
    drop(handoff);
    // Enroll while the helper is still blocked on stdin, before any unshare or fork.
    std::fs::write(group.path.join("cgroup.procs"), child.id().to_string())?;
    let exceeded = Arc::new(AtomicBool::new(false));
    let out = capture(
        child.stdout.take().unwrap(),
        config.output_limit_bytes,
        exceeded.clone(),
    );
    let err = capture(
        child.stderr.take().unwrap(),
        config.output_limit_bytes,
        exceeded.clone(),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let control = std::thread::spawn(move || -> Result<()> {
        for line in BufReader::new(read.take(16384)).lines() {
            let v: serde_json::Value = serde_json::from_str(&line?)?;
            let _ = tx.send(v);
        }
        Ok(())
    });
    if let Err(e) = child.stdin.take().unwrap().write_all(&input) {
        group.kill()?;
        bail!("helper configuration handoff failed: {e}")
    }
    let mut ready = None;
    let mut code = None;
    let mut signal = None;
    let mut launch_failed = false;
    let mut setup_failed = false;
    let mut reason = None;
    loop {
        while let Ok(v) = rx.try_recv() {
            match v["kind"].as_str() {
                Some("ready") => ready = Some(start.elapsed().as_micros() as u64),
                Some("exit") => {
                    code = v["code"].as_i64().map(|n| n as i32);
                    signal = v["signal"].as_i64().map(|n| n as i32)
                }
                Some("launch_failed") => launch_failed = true,
                Some("setup_failed") => setup_failed = true,
                _ => setup_failed = true,
            }
            chain.append(serde_json::json!({"kind":"helper","record":v}))?;
        }
        if cancel.is_closed() {
            reason = Some("cancelled");
            break;
        }
        if exceeded.load(Ordering::Acquire) {
            reason = Some("output_limit");
            break;
        }
        if start.elapsed() >= Duration::from_millis(config.timeout_ms) {
            reason = Some("timeout");
            break;
        }
        if child.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let execution_end = start.elapsed().as_micros() as u64;
    let cleanup = Instant::now();
    group.kill()?;
    let resources = group.finish()?;
    child.wait()?;
    control
        .join()
        .map_err(|_| anyhow::anyhow!("control reader panicked"))??;
    while let Ok(v) = rx.try_recv() {
        match v["kind"].as_str() {
            Some("ready") => {
                ready.get_or_insert(execution_end);
            }
            Some("exit") => {
                code = v["code"].as_i64().map(|n| n as i32);
                signal = v["signal"].as_i64().map(|n| n as i32)
            }
            Some("launch_failed") => launch_failed = true,
            Some("setup_failed") => setup_failed = true,
            _ => setup_failed = true,
        }
        chain.append(serde_json::json!({"kind":"helper","record":v}))?;
    }
    let stdout = out
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader panicked"))??;
    let stderr = err
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader panicked"))??;
    let termination = if resources["memory_events"]["oom_kill"].as_u64().unwrap_or(0) > 0 {
        "killed_by_oom"
    } else if let Some(r) = reason {
        r
    } else if exceeded.load(Ordering::Acquire) {
        "output_limit"
    } else if setup_failed || ready.is_none() {
        "initialization_failed"
    } else if launch_failed {
        "exec_failed"
    } else if signal == Some(libc::SIGSYS) {
        "seccomp"
    } else if signal.is_some() {
        "signal"
    } else if code.is_some() {
        "exited"
    } else {
        "helper_failed"
    };
    let mut outcome = Outcome {
        version: 1,
        run_id,
        termination: termination.into(),
        exit_code: code,
        signal,
        setup_ready: ready.is_some(),
        cleanup_complete: true,
        timings_us: serde_json::json!({"call_to_setup_ready":ready,"ready_to_helper_exit":ready.map(|r|execution_end.saturating_sub(r)),"cleanup_and_capture":cleanup.elapsed().as_micros()as u64,"total":start.elapsed().as_micros()as u64}),
        resources,
        stdout,
        stderr,
        audit_root: String::new(),
    };
    chain.append(serde_json::json!({"kind":"outcome","outcome":outcome}))?;
    outcome.audit_root = chain.root();
    Ok(outcome)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_invalid_config_without_execution() {
        let c:Config=serde_json::from_value(serde_json::json!({"rootfs":"/","helper":"/does-not-exist","cgroup_parent":"/missing","audit_path":"/missing","argv":["/bin/true"],"memory_bytes":33554432,"tmp_bytes":1048576,"pids":16,"cpu_quota_us":10000,"timeout_ms":100,"output_limit_bytes":1024,"deny_mode":"kill"})).unwrap();
        assert!(run(c).await.is_err());
    }
    #[test]
    fn unknown_configuration_is_rejected() {
        assert!(serde_json::from_str::<Config>("{\"allow_network\":true}").is_err());
    }
}
