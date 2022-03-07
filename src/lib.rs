use base64;
use hex::{FromHex, ToHex};

pub fn from_hex(h: &str) -> Option<Vec<u8>> {
    Vec::<u8>::from_hex(h).ok()
}

pub fn to_hex(b: &[u8]) -> String {
    b.encode_hex()
}

pub fn from_base64(b: &str) -> Option<Vec<u8>> {
    base64::decode(b).ok()
}

pub fn to_base64(bb: &[u8]) -> String {
    base64::encode(bb)
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len();
    let m = b.len();

    let mut c = Vec::<u8>::new();
    for i in 0..n {
        c.push(a[i] ^ b[i % m])
    }

    c
}

pub fn count(b: &[u8], cc: &[u8]) -> u32 {
    let mut sum: u32 = 0;

    for ch in b {
        for c in cc {
            if *ch == *c {
                sum += 1;
            }
        }
    }

    sum
}

pub struct ScoredXOR {
    pub result: String,
    pub score: u32,
    pub key: u8,
}

pub fn best_xor(m: &[u8]) -> ScoredXOR {
    let mut result = ScoredXOR {
        result: String::new(),
        score: 0,
        key: 0,
    };

    for i in 0..=255 {
        let res = xor(&m, &vec![i]);
        match String::from_utf8(res) {
            Ok(r) => {
                let char_counts = count(r.as_bytes(), String::from(" eEtTAINOSainos").as_bytes());
                if char_counts > result.score {
                    result.score = char_counts;
                    result.key = i;
                    result.result = r.to_string()
                }
            }
            Err(_) => continue,
        }
    }

    result
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let mut distance: u32 = 0;
    for mut b in xor(a, b) {
        while b > 0 {
            distance += 1;
            b &= b - 1;
        }
    }

    distance
}

fn best_keysize(bb: &[u8]) -> usize {
    let mut best: usize = 0;
    let mut lowest: f32 = 8.;
    for i in 2..=40 {
        let a = &bb[0 * i..1 * i];
        let b = &bb[1 * i..2 * i];
        let c = &bb[2 * i..3 * i];
        let d = &bb[3 * i..4 * i];

        let d: f32 = (hamming_distance(a, b)
            + hamming_distance(a, c)
            + hamming_distance(a, d)
            + hamming_distance(b, c)
            + hamming_distance(b, d)
            + hamming_distance(c, d)) as f32
            / i as f32
            / 6.;
        if d < lowest {
            lowest = d;
            best = i;
        }
    }

    best
}

pub fn find_key(bb: &[u8]) -> Vec<u8> {
    let k = best_keysize(&bb);

    let mut key = Vec::<u8>::new();

    for i in 0..k {
        let mut block = Vec::<u8>::new();
        for (j, b) in bb.iter().enumerate() {
            if j % k == i {
                block.push(*b);
            }
        }
        key.push(best_xor(&block).key);
    }

    key
}
