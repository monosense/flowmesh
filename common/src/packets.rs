use serde::{Deserialize, Serialize};

enum Opcode {
    Authorization = 0x01,
    AuthorizationReply = 0x02,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizationPacket {
    pub opcode: u8,
    pub token: [u8; 32],
    /* more data... */
}

impl AuthorizationPacket {
    pub fn new(token: [u8; 32]) -> Self {
        Self {
            opcode: Opcode::Authorization as u8,
            token,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizationReplyPacket {
    pub opcode: u8,
    pub status: u8,
}

impl AuthorizationReplyPacket {
    pub fn new(status: u8) -> Self {
        Self {
            opcode: Opcode::AuthorizationReply as u8,
            status,
        }
    }
}
