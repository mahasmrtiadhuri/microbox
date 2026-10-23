//! Narrow HTTPS GET capability. It never forwards arbitrary TCP, cookies or caller headers.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Mutex, Notify, Semaphore},
    task::JoinSet,
};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub socket: PathBuf,
    pub audit_path: PathBuf,
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub dns_pins: BTreeMap<String, Vec<IpAddr>>,
    #[serde(default)]
    pub additional_ca_pem: Option<PathBuf>,
    pub max_response_bytes: usize,
    pub max_requests: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.allowed_hosts.is_empty()
            || self.allowed_hosts.len() > 64
            || self.max_response_bytes == 0
            || self.max_response_bytes > 1024 * 1024
            || self.max_requests == 0
            || self.max_requests > 1024
            || self.concurrency == 0
            || self.concurrency > 32
            || self.timeout_ms < 100
            || self.timeout_ms > 30000
        {
            bail!("invalid bounded egress policy")
        }
        let mut seen = BTreeSet::new();
        for h in &self.allowed_hosts {
            if !valid_host(h) || !seen.insert(h) {
                bail!("allowlist requires unique canonical DNS names")
            }
        }
        for (host, ips) in &self.dns_pins {
            if !self.allowed_hosts.contains(host) {
                bail!("DNS pin must belong to allowlist")
            }
            validate_addresses(ips)?;
        }
        if !self.socket.is_absolute()
            || !self.audit_path.is_absolute()
            || self.socket == self.audit_path
        {
            bail!("absolute distinct socket and audit paths required")
        }
        let p = self.socket.parent().context("socket parent")?;
        let m = std::fs::symlink_metadata(p)?;
        if !m.is_dir() || m.mode() & 0o077 != 0 || p.canonicalize()? != p {
            bail!("socket parent must be canonical and private (0700)")
        }
        Ok(())
    }
}
fn valid_host(h: &str) -> bool {
    h.is_ascii()
        && h.len() <= 253
        && h.parse::<IpAddr>().is_err()
        && h.contains('.')
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}
/// Conservative public-unicast policy. Unknown/reserved ranges fail closed.
pub fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let [a, b, c, _] = a.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && s[0] != 0x3fff
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
        }
    }
}
fn validate_addresses(ips: &[IpAddr]) -> Result<()> {
    if ips.is_empty() || ips.len() > 32 || ips.iter().any(|a| !public_address(*a)) {
        bail!("destination_not_public")
    }
    Ok(())
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fetch {
    pub url: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Response {
    Fetched {
        status: u16,
        body_hex: String,
        peer_ip: IpAddr,
    },
    Denied {
        reason: String,
    },
}
impl Response {
    fn denied(reason: &str) -> Self {
        Self::Denied {
            reason: reason.into(),
        }
    }
}
pub fn authorize(policy: &Policy, text: &str) -> Result<reqwest::Url> {
    if text.len() > 4096 || text.chars().any(char::is_control) {
        bail!("invalid_url")
    }
    let url = reqwest::Url::parse(text).map_err(|_| anyhow::anyhow!("invalid_url"))?;
    let host = url.host_str().context("missing_host")?;
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !valid_host(host)
        || !policy.allowed_hosts.iter().any(|h| h == host)
    {
        bail!("url_not_authorized")
    }
    Ok(url)
}
struct State {
    policy: Policy,
    ca: Option<reqwest::Certificate>,
    audit: Mutex<microbox::audit::Chain<std::fs::File>>,
    failed: AtomicBool,
    stop: Notify,
}
impl State {
    async fn record(&self, event: serde_json::Value) -> Result<()> {
        let result = self.audit.lock().await.append(event);
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
            self.stop.notify_one();
        }
        result
    }
    async fn fetch(&self, request: Fetch) -> Response {
        let url = match authorize(&self.policy, &request.url) {
            Ok(u) => u,
            Err(_) => return Response::denied("url_not_authorized"),
        };
        let host = url.host_str().unwrap().to_string();
        let ips = if let Some(p) = self.policy.dns_pins.get(&host) {
            p.clone()
        } else {
            match tokio::net::lookup_host((host.as_str(), 443)).await {
                Ok(a) => a.take(33).map(|a| a.ip()).collect(),
                Err(_) => return Response::denied("dns_failed"),
            }
        };
        if validate_addresses(&ips).is_err() {
            return Response::denied("destination_not_public");
        }
        // Pin transport to exactly one validated address while preserving TLS SNI/hostname checks.
        let peer = SocketAddr::new(ips[0], 443);
        if self.failed.load(Ordering::Acquire) {
            return Response::denied("audit_unavailable");
        }
        if self
            .record(serde_json::json!({"kind":"authorized_fetch","host":host,"peer_ip":peer.ip()}))
            .await
            .is_err()
        {
            return Response::denied("audit_unavailable");
        }
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(self.policy.timeout_ms))
            .connect_timeout(Duration::from_millis(self.policy.timeout_ms))
            .resolve(&host, peer)
            .user_agent("microbox-egress/0.2");
        if let Some(ca) = &self.ca {
            builder = builder.add_root_certificate(ca.clone());
        }
        let client = match builder.build() {
            Ok(c) => c,
            Err(_) => return Response::denied("client_failed"),
        };
        let mut response = match client.get(url).send().await {
            Ok(r) => r,
            Err(_) => return Response::denied("tls_or_network_failed"),
        };
        if response.status().is_redirection() {
            return Response::denied("redirect_denied");
        }
        if response
            .content_length()
            .is_some_and(|n| n > self.policy.max_response_bytes as u64)
        {
            return Response::denied("response_too_large");
        }
        let status = response.status().as_u16();
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if chunk.len() > self.policy.max_response_bytes - body.len() {
                        return Response::denied("response_too_large");
                    }
                    body.extend_from_slice(&chunk)
                }
                Ok(None) => break,
                Err(_) => return Response::denied("response_read_failed"),
            }
        }
        Response::Fetched {
            status,
            body_hex: hex::encode(body),
            peer_ip: peer.ip(),
        }
    }
}
async fn request(stream: &mut UnixStream) -> Result<Fetch> {
    let mut bytes = Vec::new();
    let mut b = [0; 512];
    loop {
        let n = stream.read(&mut b).await?;
        if n == 0 {
            bail!("incomplete_request")
        };
        if bytes.len() + n > 4096 {
            bail!("request_too_large")
        };
        bytes.extend_from_slice(&b[..n]);
        if let Some(end) = bytes.iter().position(|b| *b == b'\n') {
            if end + 1 != bytes.len() {
                bail!("pipelining_denied")
            };
            return serde_json::from_slice(&bytes[..end]).context("malformed_request");
        }
    }
}
async fn handle(mut stream: UnixStream, state: Arc<State>) -> Result<()> {
    let limit = Duration::from_millis(state.policy.timeout_ms);
    let response = match tokio::time::timeout(limit, async {
        match request(&mut stream).await {
            Ok(r) => state.fetch(r).await,
            Err(_) => Response::denied("malformed_request"),
        }
    })
    .await
    {
        Ok(r) => r,
        Err(_) => Response::denied("request_timeout"),
    };
    // Commit metadata before returning any fetched content. Never log URL queries or response bodies.
    let metadata = match &response {
        Response::Fetched {
            status,
            body_hex,
            peer_ip,
        } => {
            serde_json::json!({"kind":"fetch_outcome","status":status,"body_bytes":body_hex.len()/2,"peer_ip":peer_ip})
        }
        Response::Denied { reason } => serde_json::json!({"kind":"fetch_outcome","denied":reason}),
    };
    state.record(metadata).await?;
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    let _ = tokio::time::timeout(limit, stream.write_all(&bytes)).await;
    Ok(())
}
struct SocketGuard(PathBuf);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
/// Run a bounded session. Shutdown stops admission, drains timed requests, then returns an audit root.
pub async fn serve(
    policy: Policy,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<String> {
    use std::os::unix::fs::OpenOptionsExt;
    if unsafe { libc::geteuid() } != 65533 || unsafe { libc::getegid() } != 65533 {
        bail!("egress service requires dedicated UID/GID 65533")
    }
    policy.validate()?;
    let ca = policy
        .additional_ca_pem
        .as_ref()
        .map(|p| {
            std::fs::read(p)
                .and_then(|b| reqwest::Certificate::from_pem(&b).map_err(std::io::Error::other))
        })
        .transpose()?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&policy.audit_path)?;
    let listener = UnixListener::bind(&policy.socket)?;
    let _guard = SocketGuard(policy.socket.clone());
    std::fs::set_permissions(&policy.socket, std::fs::Permissions::from_mode(0o666))?;
    let state = Arc::new(State {
        policy,
        ca,
        audit: Mutex::new(microbox::audit::Chain::new(file)),
        failed: AtomicBool::new(false),
        stop: Notify::new(),
    });
    state
        .record(serde_json::json!({"kind":"egress_policy","policy":state.policy}))
        .await?;
    println!(
        "{}",
        serde_json::json!({"ready":true,"socket":state.policy.socket})
    );
    let permits = Arc::new(Semaphore::new(state.policy.concurrency));
    let mut jobs = JoinSet::new();
    tokio::pin!(shutdown);
    for _ in 0..state.policy.max_requests {
        let (stream, _) = tokio::select! {r=listener.accept()=>r?,_=&mut shutdown=>break,_=state.stop.notified()=>break};
        match permits.clone().try_acquire_owned() {
            Ok(permit) => {
                let state = state.clone();
                jobs.spawn(async move {
                    let _permit = permit;
                    handle(stream, state).await
                });
            }
            Err(_) => {
                drop(stream);
                state
                    .record(serde_json::json!({"kind":"busy_connection_rejected"}))
                    .await?;
            }
        }
    }
    drop(listener);
    while let Some(result) = jobs.join_next().await {
        result.context("egress task panicked")??;
    }
    if state.failed.load(Ordering::Acquire) {
        bail!("egress audit failed; session closed")
    }
    state
        .record(serde_json::json!({"kind":"egress_session_closed"}))
        .await?;
    let root = state.audit.lock().await.root();
    Ok(root)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        Policy {
            socket: "/tmp/proxy.sock".into(),
            audit_path: "/tmp/proxy.audit".into(),
            allowed_hosts: vec!["example.com".into()],
            dns_pins: BTreeMap::new(),
            additional_ca_pem: None,
            max_response_bytes: 1024,
            max_requests: 32,
            concurrency: 4,
            timeout_ms: 1000,
        }
    }
    #[test]
    fn canonical_hosts_only() {
        for h in [
            "localhost",
            "EXAMPLE.com",
            "example.com.",
            "*.example.com",
            "127.0.0.1",
            "-bad.example",
            "example..com",
        ] {
            assert!(!valid_host(h), "{h}")
        }
        assert!(valid_host("example.com"));
    }
    #[test]
    fn strict_https_scope() {
        let p = policy();
        assert!(authorize(&p, "https://example.com/path?q=x").is_ok());
        for u in [
            "http://example.com/",
            "https://example.com:444/",
            "https://example.com.evil/",
            "https://user:pass@example.com/",
            "https://example.com/#fragment",
            "https://127.0.0.1/",
            "https://example.com./",
        ] {
            assert!(authorize(&p, u).is_err(), "{u}")
        }
    }
    #[test]
    fn private_reserved_and_transition_ranges_denied() {
        for ip in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.31.0.1",
            "192.0.2.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "fe80::1",
            "fc00::1",
            "2002:0808:0808::1",
            "2001:db8::1",
            "2001::1",
            "3fff::1",
        ] {
            assert!(!public_address(ip.parse().unwrap()), "{ip}")
        }
    }
    #[test]
    fn public_unicast_allowed() {
        for ip in [
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(public_address(ip.parse().unwrap()), "{ip}")
        }
    }
    #[test]
    fn mixed_resolution_is_rejected() {
        assert!(
            validate_addresses(&["8.8.8.8".parse().unwrap(), "127.0.0.1".parse().unwrap()])
                .is_err()
        );
        assert!(validate_addresses(&[]).is_err());
    }
    #[test]
    fn request_cannot_inject_headers_or_methods() {
        assert!(
            serde_json::from_str::<Fetch>(r#"{"url":"https://example.com","method":"POST"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Fetch>(
            r#"{"url":"https://example.com","headers":{"Host":"localhost"}}"#
        )
        .is_err());
    }
}
