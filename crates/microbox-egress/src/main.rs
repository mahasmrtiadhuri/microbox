use anyhow::{bail, Result};
#[tokio::main]
async fn main() {
    if let Err(e) = entry().await {
        eprintln!("{}", serde_json::json!({"error":format!("{e:#}")}));
        std::process::exit(1)
    }
}
async fn entry() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || args[1] != "serve" {
        bail!("usage: microbox-egress serve POLICY.json")
    }
    if std::fs::metadata(&args[2])?.len() > 65536 {
        bail!("oversized policy")
    }
    let policy: microbox_egress::Policy = serde_json::from_reader(std::fs::File::open(&args[2])?)?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let root = microbox_egress::serve(policy, async {
        tokio::select! {_ =tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
    })
    .await?;
    println!("{}", serde_json::json!({"audit_root":root}));
    Ok(())
}
