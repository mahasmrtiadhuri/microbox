use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub sequence: u64,
    pub event: serde_json::Value,
    pub digest: String,
}
fn next(previous: &[u8; 32], sequence: u64, event: &serde_json::Value) -> Result<[u8; 32]> {
    let b = serde_json::to_vec(event)?;
    let mut h = Sha256::new();
    h.update(b"MICROBOX-AUDIT-V1\0");
    h.update(previous);
    h.update(sequence.to_be_bytes());
    h.update((b.len() as u64).to_be_bytes());
    h.update(&b);
    Ok(h.finalize().into())
}
pub struct Chain<W: Write> {
    writer: W,
    sequence: u64,
    root: [u8; 32],
}
impl<W: Write> Chain<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            sequence: 0,
            root: [0; 32],
        }
    }
    pub fn append(&mut self, event: serde_json::Value) -> Result<()> {
        self.root = next(&self.root, self.sequence, &event)?;
        let r = Record {
            sequence: self.sequence,
            event,
            digest: hex::encode(self.root),
        };
        serde_json::to_writer(&mut self.writer, &r)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        self.sequence += 1;
        Ok(())
    }
    pub fn root(&self) -> String {
        hex::encode(self.root)
    }
}
pub fn verify(reader: impl BufRead, expected_root: &str) -> Result<u64> {
    if expected_root.len() != 64 {
        bail!("a separately retained 32-byte root is required")
    };
    let mut root = [0; 32];
    let mut count = 0;
    for line in reader.lines() {
        let line = line?;
        if line.len() > 1024 * 1024 {
            bail!("oversized audit record")
        };
        let r: Record = serde_json::from_str(&line)?;
        if r.sequence != count {
            bail!("sequence mismatch")
        };
        root = next(&root, count, &r.event)?;
        if hex::encode(root) != r.digest {
            bail!("record digest mismatch")
        };
        count += 1;
    }
    if hex::encode(root) != expected_root {
        bail!("external root mismatch: truncated or replaced log")
    };
    Ok(count)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn anchored_chain_detects_changes() {
        let mut bytes = Vec::new();
        let mut c = Chain::new(&mut bytes);
        c.append(serde_json::json!({"a":1})).unwrap();
        c.append(serde_json::json!({"b":2})).unwrap();
        let root = c.root();
        assert_eq!(verify(&bytes[..], &root).unwrap(), 2);
        let first = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
        assert!(verify(&bytes[..first], &root).is_err());
        let mut changed = bytes.clone();
        let i = changed.iter().position(|b| *b == b'a').unwrap();
        changed[i] = b'x';
        assert!(verify(&changed[..], &root).is_err());
    }
    #[test]
    fn requires_external_anchor() {
        assert!(verify(&b""[..], "").is_err());
    }
}
