use bincode;
use common::packets::AuthorizationPacket;
use hex;
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

const AUTHTOKEN: &str = "1a413d012682eb10342cdf7f0e33dd61c2b20e79e4c23feba399919f76d5b408";

enum ProviderPassedState {
    None,
}

async fn process(mut socket: TcpStream) {
    println!("accepted a provider");
    let mut buf = [0u8; 1024];
    let passed = ProviderPassedState::None;
    loop {
        let n = match socket.read(&mut buf).await {
            Ok(0) => {
                println!("provider socket has disconnected");
                return;
            }
            Ok(n) => n,
            Err(e) => {
                eprintln!("failed to read from provider socket, err: {e}");
                return;
            }
        };

        println!("read {n} bytes from provider");

        match passed {
            ProviderPassedState::None => {
                let authp: AuthorizationPacket = match bincode::deserialize(&buf[..n]) {
                    Ok(data) => data,
                    Err(_) => {
                        println!("failed to deserialize provider data");
                        return;
                    }
                };

                println!("authp: {:?}", authp);
                if hex::encode(authp.token) == AUTHTOKEN {
                    println!("got correct auth token");
                    /* TODO: respond accordingly */
                } else {
                    println!("incorrect auth token");
                    /* TODO: respond accordingly */
                    return;
                }
            }
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
