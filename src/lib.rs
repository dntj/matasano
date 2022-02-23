use base64::encode;
use hex::{FromHex, ToHex};
use std::str;

pub fn from_hex(h: String) -> Option<Vec<u8>> {
    Vec::<u8>::from_hex(h).ok()
}

pub fn to_hex(b: Vec<u8>) -> String {
    return b.encode_hex();
}

pub fn to_base64(bb: Vec<u8>) -> String {
    encode(bb)
}

pub fn xor(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    let n = a.len();
    let m = b.len();

    let mut c = Vec::<u8>::new();
    for i in 0..n {
        c.push(a[i] ^ b[i % m])
    }

    return c;
}

pub fn count(b: &Vec<u8>, c: u8) -> i32 {
    let mut sum: i32 = 0;

    for ch in b {
        if *ch == c {
            sum += 1;
        }
    }
    return sum;
}

pub struct Result {
    pub n_spaces: i32,
    pub result: String,
}

pub fn best_xor(m: &Vec<u8>) -> Result {
    let mut result = Result {
        n_spaces: -1,
        result: String::new(),
    };

    for i in 0..=255 {
        let res = xor(&m, &vec![i]);
        match str::from_utf8(&res) {
            Ok(r) => {
                let n_spaces = count(&res, String::from(' ').as_bytes()[0]);
                if n_spaces > result.n_spaces {
                    result.n_spaces = n_spaces;
                    result.result = r.to_string()
                }
            }
            Err(_) => continue,
        }
    }

    return result;
}
