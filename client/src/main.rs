use common::packets::{AuthorizationPacket, AuthorizationReplyPacket, AuthorizationStatus};
use std::io;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpSocket,
};

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Unauthorized access")]
    Unauthorized,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Deserialization error: {0}")]
    Deserialize(#[from] bincode::Error),
    #[error("Hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),
}

const AUTHTOKEN: &str = "1a413d012682eb10342cdf7f0e33dd61c2b20e79e4c23feba399919f76d5b409";

#[tokio::main]
async fn main() -> Result<(), AuthError> {
    let addr = "127.0.0.1:1081".parse().unwrap();

    let socket = TcpSocket::new_v4()?;
    let mut stream = socket.connect(addr).await?;

    println!("connected to the server! {:?}", stream);

    let token_arr: [u8; 32] = hex::decode(AUTHTOKEN)?.try_into().unwrap();
    let authp = AuthorizationPacket::new(token_arr);

    println!("authp: {:?}", authp);

    let serialized = bincode::serialize(&authp)?;
    println!("serialized: {:?}", serialized);
    stream.write_all(&serialized).await?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Err(
            io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed by peer").into(),
        );
    }

    let authresp: AuthorizationReplyPacket = bincode::deserialize(&buf[..n])?;
    println!("authresp: {:?}", authresp);

    if authresp.status == AuthorizationStatus::Ok as u8 {
        println!("authorized successfully");

        /* do something */
    } else {
        return Err(AuthError::Unauthorized);
    }

    Ok(())
}
