use tokio::net::TcpListener;

pub async fn run(addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    //loop {
    //}
    Ok(()) // temporary
}
