use crate::{Config, InitializationError};
use anyhow::{bail, Context, Result};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
pub struct Group {
    pub path: PathBuf,
    pub removed: bool,
}
impl Drop for Group {
    fn drop(&mut self) {
        if !self.removed {
            let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}
fn write(path: &Path, name: &str, value: impl AsRef<[u8]>) -> Result<()> {
    std::fs::write(path.join(name), value).with_context(|| format!("write cgroup setting {name}"))
}
impl Group {
    pub fn create(c: &Config) -> Result<Self> {
        if !microbox_sys::cgroup2(&c.cgroup_parent)? {
            return Err(InitializationError::MissingCgroupV2.into());
        }
        if !c.cgroup_parent.join("cgroup.kill").is_file() {
            return Err(InitializationError::MissingCgroupKillSupport.into());
        }
        let available = std::fs::read_to_string(c.cgroup_parent.join("cgroup.controllers"))?;
        for needed in ["cpu", "memory", "pids"] {
            if !available.split_whitespace().any(|a| a == needed) {
                return Err(InitializationError::MissingController(needed.into()).into());
            }
        }
        if !std::fs::read_to_string(c.cgroup_parent.join("cgroup.procs"))?
            .trim()
            .is_empty()
        {
            bail!("delegation parent must contain no processes")
        }
        // Explicitly provided dedicated delegation only. Never modify ancestor controller settings.
        write(
            &c.cgroup_parent,
            "cgroup.subtree_control",
            "+cpu +memory +pids",
        )?;
        let path = c
            .cgroup_parent
            .join(format!("run-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path)?;
        let g = Self {
            path,
            removed: false,
        };
        for n in [
            "cgroup.kill",
            "memory.peak",
            "cpu.stat",
            "memory.events",
            "pids.events",
        ] {
            if !g.path.join(n).is_file() {
                bail!("required cgroup interface missing: {n}")
            }
        }
        write(&g.path, "memory.max", c.memory_bytes.to_string())?;
        write(&g.path, "memory.swap.max", "0")?;
        write(&g.path, "memory.oom.group", "1")?;
        write(&g.path, "pids.max", c.pids.to_string())?;
        write(&g.path, "cpu.max", format!("{} 100000", c.cpu_quota_us))?;
        Ok(g)
    }
    pub fn kill(&self) -> Result<()> {
        write(&self.path, "cgroup.kill", "1")
    }
    pub fn stats(&self) -> Result<serde_json::Value> {
        Ok(
            serde_json::json!({"memory_peak_bytes":std::fs::read_to_string(self.path.join("memory.peak"))?.trim().parse::<u64>()?,"cpu":parse(&std::fs::read_to_string(self.path.join("cpu.stat"))?)?,"memory_events":parse(&std::fs::read_to_string(self.path.join("memory.events"))?)?,"pids_events":parse(&std::fs::read_to_string(self.path.join("pids.events"))?)?}),
        )
    }
    pub fn finish(&mut self) -> Result<serde_json::Value> {
        self.kill()?;
        let start = Instant::now();
        loop {
            let events = parse(&std::fs::read_to_string(self.path.join("cgroup.events"))?)?;
            if events.get("populated") == Some(&0) {
                break;
            }
            if start.elapsed() > Duration::from_secs(5) {
                bail!(
                    "CleanupFailed: cgroup remains populated after kill; retained at {}",
                    self.path.display()
                )
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let stats = self.stats()?;
        std::fs::remove_dir(&self.path).context("CleanupFailed: remove empty cgroup")?;
        self.removed = true;
        Ok(stats)
    }
}
fn parse(s: &str) -> Result<std::collections::BTreeMap<String, u64>> {
    s.lines()
        .map(|l| {
            let mut p = l.split_whitespace();
            let k = p.next().context("missing cgroup metric name")?.to_string();
            let n = p.next().context("missing cgroup metric value")?.parse()?;
            Ok((k, n))
        })
        .collect()
}
