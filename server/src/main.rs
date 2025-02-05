mod consumer_server;
mod provider_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cserver = tokio::spawn(consumer_server::run("127.0.0.1:1080"));
    let pserver = tokio::spawn(provider_server::run("127.0.0.1:1081"));
    let _ = tokio::try_join!(cserver, pserver);
    Ok(())
}
