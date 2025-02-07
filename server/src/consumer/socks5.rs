use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::error::SOCKS5Error;
use tokio::{
    io::AsyncWriteExt,
    net::{lookup_host, TcpStream},
};

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_SUBNEGOTIATION_VERSION: u8 = 0x01;
const SOCKS5_RESERVE: u8 = 0x00;

enum SOCKS5Status {
    Ok,
    _Error,
}

enum SOCKS5Method {
    _NoAuth,
    _GSSApi,
    UserPass,
    None = 0xff,
}

enum SOCKS5Command {
    Connect = 0x01,
    _Bind = 0x02,
    _Udp = 0x03,
}

enum SOCKS5AddrType {}
impl SOCKS5AddrType {
    const IPV4: u8 = 0x01;
    const DOMAIN: u8 = 0x03;
    const IPV6: u8 = 0x04;
}

pub async fn handle_identification(socket: &mut TcpStream, buf: &[u8]) -> Result<(), SOCKS5Error> {
    if buf.len() < 2 || buf[0] != SOCKS5_VERSION || buf[1] == 0 || buf.len() != buf[1] as usize + 2
    {
        println!("received an invalid socks5 id packet");
        let _ = socket.shutdown().await;
        return Err(SOCKS5Error::MalformedPacket);
    }

    println!("methods: {:?}", &buf[2..]);

    if !buf[2..].contains(&(SOCKS5Method::UserPass as u8)) {
        println!("consumer did not offer user/pass");
        let _ = socket
            .write_all(&[SOCKS5_VERSION, SOCKS5Method::None as u8])
            .await;
        let _ = socket.shutdown().await;
        return Err(SOCKS5Error::IDMethodNotFound);
    }

    let _ = socket
        .write_all(&[SOCKS5_VERSION, SOCKS5Method::UserPass as u8])
        .await;

    Ok(())
}

pub async fn handle_authentification(
    socket: &mut TcpStream,
    buf: &[u8],
) -> Result<(), SOCKS5Error> {
    if buf.len() < 2 || buf[0] != SOCKS5_SUBNEGOTIATION_VERSION {
        let _ = socket.shutdown().await;
        return Err(SOCKS5Error::MalformedPacket);
    }

    let ulen: u8 = buf[1];
    if ulen == 0 || buf.len() < ulen as usize + 2 {
        let _ = socket.shutdown().await;
        return Err(SOCKS5Error::MalformedPacket);
    }

    let username = String::from_utf8_lossy(&buf[2..ulen as usize + 2]);
    println!("username: {username}");

    let plen: u8 = buf[ulen as usize + 2];
    if plen == 0 || buf.len() != ulen as usize + plen as usize + 3 {
        println!("invalid auth packet size");
        let _ = socket.shutdown().await;
        return Err(SOCKS5Error::MalformedPacket);
    }

    let password = String::from_utf8_lossy(&buf[ulen as usize + 3..buf.len()]);
    println!("password: {password}");

    // accept any auth now
    let _ = socket
        .write_all(&[SOCKS5_SUBNEGOTIATION_VERSION, SOCKS5Status::Ok as u8])
        .await;

    Ok(())
}

pub async fn handle_request(socket: &mut TcpStream, buf: &[u8]) -> Result<SocketAddr, SOCKS5Error> {
    if buf.len() < 4
        || buf[0] != SOCKS5_VERSION
        || buf[1] != SOCKS5Command::Connect as u8
        || buf[2] != SOCKS5_RESERVE
    {
        let _ = socket.shutdown().await;
        return Err(SOCKS5Error::MalformedPacket);
    }

    let atyp = buf[3];
    match atyp {
        SOCKS5AddrType::IPV4 => {
            if buf.len() != 10 {
                println!("invalid request ipv4 packet");
                let _ = socket.shutdown().await;
                return Err(SOCKS5Error::MalformedPacket);
            }
            let ipv4: [u8; 4] = buf[4..8].try_into().unwrap();
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ipv4)), port))
        }
        SOCKS5AddrType::DOMAIN => {
            if buf.len() < 5 {
                println!("invalid request domain packet");
                let _ = socket.shutdown().await;
                return Err(SOCKS5Error::MalformedPacket);
            }

            let domainlen: u8 = buf[4];
            if domainlen == 0 || buf.len() != domainlen as usize + 7 {
                println!("invalid request packet. bad length");
                let _ = socket.shutdown().await;
                return Err(SOCKS5Error::MalformedPacket);
            }

            let domain = String::from_utf8_lossy(&buf[5..domainlen as usize + 5]);
            println!("domain: {domain}, len {}", domain.len());

            let port =
                u16::from_be_bytes([buf[domainlen as usize + 5], buf[domainlen as usize + 6]]);

            println!("port: {port}");

            // query a hostname lookup
            let mut addresses = match lookup_host(format!("{domain}:{port}")).await {
                Ok(res) => res,
                Err(_) => {
                    println!("invalid request packet. failed to lookup the hostname");
                    let _ = socket.shutdown().await;
                    return Err(SOCKS5Error::HostnameLookup);
                }
            };

            match addresses.next() {
                Some(a) => Ok(a),
                _ => {
                    let _ = socket.shutdown().await;
                    Err(SOCKS5Error::HostnameLookup)
                }
            }
        }
        SOCKS5AddrType::IPV6 => {
            if buf.len() != 22 {
                println!("invalid request ipv4 packet");
                let _ = socket.shutdown().await;
                return Err(SOCKS5Error::MalformedPacket);
            }
            let ipv6: [u8; 16] = buf[4..20].try_into().unwrap();
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ipv6)), port))
        }
        _ => {
            println!("invalid request packet");
            let _ = socket.shutdown().await;
            Err(SOCKS5Error::MalformedPacket)
        }
    }
}
