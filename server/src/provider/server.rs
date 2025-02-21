use bincode;
use common::packets::{AuthorizationPacket, AuthorizationReplyPacket, AuthorizationStatus};
use hex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const AUTHTOKEN: &str = "1a413d012682eb10342cdf7f0e33dd61c2b20e79e4c23feba399919f76d5b409";

enum ProviderPassedState {
    None,
    Authorized,
}

async fn process(mut socket: TcpStream) {
    println!("accepted a provider");
    let mut buf = [0u8; 1024];
    let mut passed = ProviderPassedState::None;
    loop {
        let n = match socket.read(&mut buf).await {
            Ok(0) => {
                println!("provider socket has disconnected");
                let _ = socket.shutdown().await;
                return;
            }
            Ok(n) => n,
            Err(e) => {
                eprintln!("failed to read from provider socket, err: {e}");
                let _ = socket.shutdown().await;
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
                        let _ = socket.shutdown().await;
                        return;
                    }
                };

                println!("authp: {:?}", authp);

                /*
                 * TODO: check if `authp.token` is valid in database
                 */

                let status = if hex::encode(authp.token) == AUTHTOKEN {
                    println!("got correct auth token");
                    passed = ProviderPassedState::Authorized;
                    AuthorizationStatus::Ok
                } else {
                    println!("incorrect auth token");
                    AuthorizationStatus::Error
                };

                let rep: AuthorizationReplyPacket = AuthorizationReplyPacket::new(status);
                let serialized = bincode::serialize(&rep).unwrap();

                if (socket.write(&serialized).await).is_err() {
                    println!("failed to write auth reply packet to provider");
                    let _ = socket.shutdown().await;
                    return;
                }

                if status != AuthorizationStatus::Ok {
                    println!("authorization status is not ok. disconnecting.");
                    let _ = socket.shutdown().await;
                    return;
                }
            }
            ProviderPassedState::Authorized => {}
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
