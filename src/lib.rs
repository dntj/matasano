use hex::{FromHex};
use base64::{encode};

pub fn from_hex(h: String) -> Option<Vec<u8>> {
    Vec::<u8>::from_hex(h).ok()
}

pub fn to_base64(bb: Vec<u8>) -> String {
    encode(bb)
}

pub fn xor(a: &Vec<u8>, b: &Vec<u8>) -> Option<Vec<u8>> {
    let n = a.len();
    let m = b.len();

    let mut c = Vec::<u8>::new();
    for i in 0..n {
        c.push(a[i] ^ b[i % m])
    }

    return Some(c)
}

pub fn count(b: &Vec<u8>, c: u8) -> i32 {
    let mut sum: i32 = 0;

    for ch in b {
        if *ch == c {
            sum += 1;
        }
    }
    return sum
}