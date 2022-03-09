use aes;
use base64;
use cipher::{BlockDecrypt, BlockEncrypt};
use crypto_common::KeyInit;
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
    let m = b.len();

    let mut c = Vec::from(a);
    for (i, v) in c.iter_mut().enumerate() {
        *v ^= b[i % m];
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
    key: u8,
}

impl ScoredXOR {
    pub fn best(m: &[u8]) -> ScoredXOR {
        let mut result = ScoredXOR {
            result: String::new(),
            score: 0,
            key: 0,
        };

        for i in 0..=255 {
            let res = xor(&m, &vec![i]);
            match String::from_utf8(res) {
                Ok(r) => {
                    let char_counts = count(r.as_bytes(), b" eEtTAINOSainos");
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
        key.push(ScoredXOR::best(&block).key);
    }

    key
}

pub fn aes128_encrypt_ecb(k: &[u8], enc: &[u8]) -> Result<Vec<u8>, String> {
    let k_res = aes::Aes128::new_from_slice(k);
    if let Err(_) = k_res {
        return Err("bad key".to_string());
    }

    let k = k_res.unwrap();

    let mut bb = Vec::from(enc);
    for i in 0..(bb.len() / 16) {
        let mut block = aes::Block::from_mut_slice(&mut bb[i * 16..(i + 1) * 16]);
        k.encrypt_block(&mut block);
    }

    Ok(bb)
}

pub fn aes128_decrypt_ecb(k: &[u8], enc: &[u8]) -> Result<Vec<u8>, String> {
    let k_res = aes::Aes128::new_from_slice(k);
    if let Err(_) = k_res {
        return Err("bad key".to_string());
    }

    let k = k_res.unwrap();

    let mut bb = Vec::from(enc);
    for i in 0..(bb.len() / 16) {
        let mut block = aes::Block::from_mut_slice(&mut bb[i * 16..(i + 1) * 16]);
        k.decrypt_block(&mut block);
    }

    Ok(bb)
}

pub fn aes128_encrypt_cbc(k: &[u8], iv: &[u8], enc: &[u8]) -> Result<Vec<u8>, String> {
    let k_res = aes::Aes128::new_from_slice(k);
    if let Err(_) = k_res {
        return Err("bad key".to_string());
    }

    let k = k_res.unwrap();
    if iv.len() != 16 {
        return Err("iv must be 16 bytes long".to_string());
    }

    let mut bb = Vec::from(enc);
    for i in 0..bb.len() / 16 {
        for j in 0..16 {
            if i == 0 {
                bb[j] ^= iv[j];
            } else {
                bb[i * 16 + j] ^= bb[(i - 1) * 16 + j];
            }
        }

        let mut block = aes::Block::from_mut_slice(&mut bb[i * 16..(i + 1) * 16]);
        k.encrypt_block(&mut block);
    }

    Ok(bb)
}

pub fn aes128_decrypt_cbc(k: &[u8], iv: &[u8], enc: &[u8]) -> Result<Vec<u8>, String> {
    let k_res = aes::Aes128::new_from_slice(k);
    if let Err(_) = k_res {
        return Err("bad key".to_string());
    }

    let k = k_res.unwrap();
    if iv.len() != 16 {
        return Err("iv must be 16 bytes long".to_string());
    }

    let mut bb = Vec::from(enc);
    let n = bb.len() / 16;
    for i in 0..n {
        let mut block = aes::Block::from_mut_slice(&mut bb[(n - 1 - i) * 16..(n - i) * 16]);

        k.decrypt_block(&mut block);

        for j in 0..16 {
            if i == n - 1 {
                bb[j] ^= iv[j];
            } else {
                bb[(n - i - 1) * 16 + j] ^= bb[(n - i - 2) * 16 + j];
            }
        }
    }

    Ok(bb)
}

pub fn pad(bb: &[u8], n: usize, c: u8) -> Vec<u8> {
    let mut padded = Vec::from(bb);

    if n > bb.len() {
        let diff = n - bb.len() % n;
        padded.extend([c].repeat(diff));
    }

    padded
}
