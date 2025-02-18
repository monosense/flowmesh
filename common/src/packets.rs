use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizationPacket {
    pub token: [u8; 32],
    /* more data... */
}
