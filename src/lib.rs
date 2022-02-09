use hex::{FromHex, FromHexError};
use base64::{encode};

pub fn from_hex(h: String) -> Result<Vec<u8>, FromHexError> {
    Vec::<u8>::from_hex(h)
}

pub fn to_base64(bb: Vec<u8>) -> String {
    encode(bb)
}
