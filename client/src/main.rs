use common::packets::AuthorizationPacket;
use std::io;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpSocket,
};

const AUTHTOKEN: &str = "1a413d012682eb10342cdf7f0e33dd61c2b20e79e4c23feba399919f76d5b408";

#[tokio::main]
async fn main() -> io::Result<()> {
    let addr = "127.0.0.1:1081".parse().unwrap();

    let socket = TcpSocket::new_v4()?;
    let mut stream = socket.connect(addr).await?;

    println!("connected to the server! {:?}", stream);

    let token_arr: [u8; 32] = hex::decode(AUTHTOKEN).unwrap().try_into().unwrap();
    let authp = AuthorizationPacket { token: token_arr };

    println!("authp: {:?}", authp);

    let serialized = bincode::serialize(&authp).unwrap();
    println!("serialized: {:?}", serialized);
    let _ = stream.write(&serialized).await?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Connection closed by peer",
        ));
    }
    // check if we have been authorized

    /*loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Connection closed by peer",
            ));
        }

        println!("n: {n}");
    }*/

    Ok(())
}
