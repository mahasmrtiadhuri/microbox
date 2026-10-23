//! cargo run --release -p microbox --example run -- config.json
use anyhow::{bail, Context, Result};
#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("configuration path required")?;
    let config: microbox::Config = serde_json::from_reader(std::fs::File::open(path)?)?;
    let outcome = microbox::run(config).await?;
    println!("{}", serde_json::to_string_pretty(&outcome)?);
    if outcome.termination != "exited" || outcome.exit_code != Some(0) {
        bail!("workload did not exit successfully");
    }
    Ok(())
}
