use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::lookup_host;
use tokio::net::{TcpListener, TcpStream};

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_SUBNEGOTIATION_VERSION: u8 = 0x01;
const SOCKS5_RESERVE: u8 = 0x00;

enum SOCKS5Status {
    Ok,
    Error,
}

enum SOCKS5Method {
    NoAuth,
    GSSApi,
    UserPass,
    None = 0xff,
}

enum SOCKS5Command {
    Connect = 0x01,
    Bind = 0x02,
    Udp = 0x03,
}

enum SOCKS5AddrType {}
impl SOCKS5AddrType {
    const IPV4: u8 = 0x01;
    const DOMAIN: u8 = 0x03;
    const IPV6: u8 = 0x04;
}

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

                if n < 2 || buf[0] != SOCKS5_VERSION || buf[1] == 0 || n != buf[1] as usize + 2 {
                    println!("received an invalid socks5 id packet");
                    let _ = socket.shutdown().await;
                    return;
                }
                println!("consumer offered {} id methods", buf[1]);
                if !buf[2..n].contains(&(SOCKS5Method::UserPass as u8)) {
                    println!("consumer did not offer user/pass");
                    let _ = socket
                        .write_all(&[SOCKS5_VERSION, SOCKS5Method::None as u8])
                        .await;
                    let _ = socket.shutdown().await;
                    return;
                }

                let _ = socket
                    .write_all(&[SOCKS5_VERSION, SOCKS5Method::UserPass as u8])
                    .await;
                passed = ConsumerPassedState::Id;
            }
            ConsumerPassedState::Id => {
                println!("handling consumer auth");

                if n < 2 || buf[0] != SOCKS5_SUBNEGOTIATION_VERSION {
                    println!("invalid auth packet");
                    let _ = socket.shutdown().await;
                    return;
                }

                let ulen: u8 = buf[1];
                if ulen == 0 || n < ulen as usize + 2 {
                    println!("invalid auth packet or size");
                    let _ = socket.shutdown().await;
                    return;
                }

                let username = String::from_utf8_lossy(&buf[2..ulen as usize + 2]);
                println!("username: {username}");

                let plen: u8 = buf[ulen as usize + 2];
                if plen == 0 || n != ulen as usize + plen as usize + 3 {
                    println!("invalid auth packet size");
                    let _ = socket.shutdown().await;
                    return;
                }

                let password = String::from_utf8_lossy(&buf[ulen as usize + 3..n]);
                println!("password: {password}");

                // accept any auth now
                let _ = socket
                    .write_all(&[SOCKS5_SUBNEGOTIATION_VERSION, SOCKS5Status::Ok as u8])
                    .await;
                passed = ConsumerPassedState::Auth;
            }
            ConsumerPassedState::Auth => {
                println!("handling consumer request");

                if n < 4
                    || buf[0] != SOCKS5_VERSION
                    || buf[1] != SOCKS5Command::Connect as u8
                    || buf[2] != SOCKS5_RESERVE
                {
                    println!("invalid request packet");
                    let _ = socket.shutdown().await;
                    return;
                }

                let atyp = buf[3];
                let addr: SocketAddr;

                match atyp {
                    SOCKS5AddrType::IPV4 => {
                        if n != 10 {
                            println!("invalid request ipv4 packet");
                            let _ = socket.shutdown().await;
                            return;
                        }
                        let ipv4: [u8; 4] = buf[4..8].try_into().unwrap();
                        let port = u16::from_be_bytes([buf[8], buf[9]]);
                        addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ipv4)), port);
                        println!("ipv4: {addr}");
                    }
                    SOCKS5AddrType::DOMAIN => {
                        if n < 5 {
                            println!("invalid request domain packet");
                            let _ = socket.shutdown().await;
                            return;
                        }

                        let domainlen: u8 = buf[4];
                        if domainlen == 0 || n != domainlen as usize + 7 {
                            println!("invalid request packet. bad length");
                            let _ = socket.shutdown().await;
                            return;
                        }

                        let domain = String::from_utf8_lossy(&buf[5..domainlen as usize + 5]);
                        println!("domain: {domain}, len {}", domain.len());

                        let port = u16::from_be_bytes([
                            buf[domainlen as usize + 5],
                            buf[domainlen as usize + 6],
                        ]);

                        println!("port: {port}");

                        // query a hostname lookup
                        let mut addresses = match lookup_host(format!("{domain}:{port}")).await {
                            Ok(res) => res,
                            Err(_) => {
                                println!("invalid request packet. failed to lookup the hostname");
                                let _ = socket.shutdown().await;
                                return;
                            }
                        };

                        match addresses.next() {
                            Some(a) => {
                                addr = a;
                            }
                            _ => {
                                println!("failed to resolve any addresses");
                                let _ = socket.shutdown().await;
                                return;
                            }
                        }
                    }
                    SOCKS5AddrType::IPV6 => {
                        if n != 22 {
                            println!("invalid request ipv4 packet");
                            let _ = socket.shutdown().await;
                            return;
                        }
                        let ipv6: [u8; 16] = buf[4..20].try_into().unwrap();
                        let port = u16::from_be_bytes([buf[20], buf[21]]);
                        addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ipv6)), port);
                        println!("ipv6: {addr}");
                    }
                    _ => {
                        println!("invalid request packet");
                        let _ = socket.shutdown().await;
                        return;
                    }
                }

                println!("addr: {addr}");
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
