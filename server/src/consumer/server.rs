use super::socks5::*;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

enum ConsumerPassedState {
    None,
    Id,
    Auth,
    Request,
}

async fn process(mut socket: TcpStream) {
    println!("consumer_server processing a socket");
    let mut buf = [0u8; 1024];
    let mut passed = ConsumerPassedState::None;
    loop {
        let n = match socket.read(&mut buf).await {
            Ok(0) => {
                println!("consumer socket has disconnected");
                return;
            }
            Ok(n) => n,
            Err(e) => {
                eprintln!("failed to read from consumer socket, err: {e}");
                return;
            }
        };

        println!("consumer has sent {n} bytes: {:?}", &buf[..n]);

        match passed {
            ConsumerPassedState::None => {
                println!("handling consumer id");
                if let Err(e) = handle_identification(&mut socket, &buf[..n]).await {
                    eprintln!("Error: {e}");
                    return;
                }
                passed = ConsumerPassedState::Id;
            }
            ConsumerPassedState::Id => {
                println!("handling consumer auth");
                if let Err(e) = handle_authentification(&mut socket, &buf[..n]).await {
                    eprintln!("Error: {e}");
                    return;
                }
                passed = ConsumerPassedState::Auth;
            }
            ConsumerPassedState::Auth => {
                println!("handling consumer request");
                if let Err(e) = handle_request(&mut socket, &buf[..n]).await {
                    eprintln!("Error: {e}");
                    return;
                }
                passed = ConsumerPassedState::Request;
            }
            ConsumerPassedState::Request => {}
        };
    }
}

pub async fn run(addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            process(socket).await;
        });
    }
}
