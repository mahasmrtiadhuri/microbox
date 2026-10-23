use anyhow::{bail, Result};
use std::{io::BufReader, path::Path};
#[tokio::main]
async fn main() {
    if let Err(e) = entry().await {
        eprintln!("{}", serde_json::json!({"error":format!("{e:#}")}));
        std::process::exit(1)
    }
}
async fn entry() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") if args.len() == 3 => {
            let c: microbox::Config = serde_json::from_reader(std::fs::File::open(Path::new(&args[2]))?)?;
            let out = microbox::run(c).await?;
            println!("{}", serde_json::to_string(&out)?);
        }
        Some("verify") if args.len() == 4 => {
            let n = microbox::audit::verify(BufReader::new(std::fs::File::open(&args[2])?), &args[3])?;
            println!("{}", serde_json::json!({"verified_records":n,"root":args[3]}));
        }
        Some("init-config") if args.len() >= 7 => {
            let config = microbox::Config::new(std::fs::canonicalize(&args[2])?, std::fs::canonicalize(&args[3])?, std::fs::canonicalize(&args[4])?, std::path::PathBuf::from(&args[5]), args[6..].to_vec());
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        Some("cancel-test") if args.len() == 3 => {
            let c: microbox::Config = serde_json::from_reader(std::fs::File::open(&args[2])?)?;
            let parent = c.cgroup_parent.clone(); let audit = c.audit_path.clone();
            let job = tokio::spawn(microbox::run(c));
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            job.abort(); let _ = job.await;
            for _ in 0..500 {
                if std::fs::read_to_string(&audit).unwrap_or_default().contains("cancelled") && !std::fs::read_dir(&parent)?.filter_map(|e|e.ok()).any(|e|e.file_name().to_string_lossy().starts_with("run-")) {
                    println!("{{\"cancelled_and_cleaned\":true}}"); return Ok(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            bail!("cancellation cleanup did not complete")
        }
        _ => bail!("usage: microbox-cli run CONFIG | verify AUDIT ROOT | init-config ROOTFS HELPER CGROUP AUDIT COMMAND [ARGS...] | cancel-test CONFIG")
    }
    Ok(())
}
