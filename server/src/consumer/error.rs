use thiserror::Error;

#[derive(Error, Debug)]
pub enum SOCKS5Error {
    #[error("Malformed packet")]
    MalformedPacket,
    #[error("Failed to find the required method for ID")]
    IDMethodNotFound,
    #[error("Failed to lookup hostnames")]
    HostnameLookup,
}
