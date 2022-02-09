use hex::{FromHex};
use base64::{encode};

pub fn from_hex(h: String) -> Option<Vec<u8>> {
    Vec::<u8>::from_hex(h).ok()
}

pub fn to_base64(bb: Vec<u8>) -> String {
    encode(bb)
}

pub fn xor(a: Vec<u8>, b: Vec<u8>) -> Option<Vec<u8>> {
    let n = a.len();
    if b.len() != n {
        return None
    }

    let mut c = Vec::<u8>::new();
    for i in 0..n {
        c.push(a[i] ^ b[i])
    }

    return Some(c)
}