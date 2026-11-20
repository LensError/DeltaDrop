#[tokio::main]
async fn main() -> anyhow::Result<()> {
    deltadrop_relay::run_cli_or_server().await
}
