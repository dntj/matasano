use base64;
use hex::{FromHex, ToHex};
use rand::{rngs::OsRng, RngCore};
use std::collections;

use crate::aes::Encrypter;

pub mod aes;
pub mod cbc;
pub mod ecb;

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

#[derive(Debug, PartialEq)]
pub enum Mode {
    ECB,
    CBC,
}

pub fn detect_block_mode(input: &[u8]) -> Mode {
    let mut counts = collections::HashMap::<&[u8], u8>::new();
    for i in 0..(input.len() / 16) {
        let k = &input[16 * i..16 * (i + 1)];
        *counts.entry(k).or_default() += 1;
    }
    for (_, v) in &counts {
        if *v > 1 {
            return Mode::CBC;
        }
    }

    Mode::ECB
}

pub struct RandomEncrypter {
    pub mode: Mode,
    pub ciphertext: Vec<u8>,
}

impl RandomEncrypter {
    pub fn new(input: &[u8]) -> Result<RandomEncrypter, &str> {
        let mut key = [0u8; 16];
        OsRng.fill_bytes(&mut key);

        let ecb = OsRng.next_u32() & 1 == 1;
        let n_pad_before = (OsRng.next_u32() % 6 + 5) as usize; // random ∈ [5, 10]
        let n_pad_after = (OsRng.next_u32() % 6 + 5) as usize; // random ∈ [5, 10]

        let mut plain = vec![0; n_pad_before];
        OsRng.fill_bytes(&mut plain);

        plain.extend(input);

        let mut suffix = vec![0; n_pad_after];
        OsRng.fill_bytes(&mut suffix);

        plain.extend(suffix);

        if ecb {
            // Choose ECB with 50% probability.
            Ok(RandomEncrypter {
                mode: Mode::ECB,
                ciphertext: aes::ECB::new(&key)?.encrypt(&plain),
            })
        } else {
            let mut iv = [0u8; 16];
            OsRng.fill_bytes(&mut iv);

            Ok(RandomEncrypter {
                mode: Mode::CBC,
                ciphertext: aes::CBC::new(&key, &iv)?.encrypt(&plain),
            })
        }
    }
}

pub struct RandomKeyCoder<T> {
    coder: T,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

impl<T> RandomKeyCoder<T> {
    pub fn new(ctor: &dyn Fn(&[u8]) -> T) -> RandomKeyCoder<T> {
        let mut key = [0u8; 16];
        OsRng.fill_bytes(&mut key);

        RandomKeyCoder {
            coder: ctor(&key),
            prefix: Vec::new(),
            suffix: Vec::new(),
        }
    }

    pub fn with_random_prefix(self) -> RandomKeyCoder<T> {
        let l = (OsRng.next_u32() % 256) as usize;
        let mut prefix = vec![0; l];
        OsRng.fill_bytes(&mut prefix);

        self.with_prefix(prefix)
    }

    pub fn with_prefix(self, prefix: Vec<u8>) -> RandomKeyCoder<T> {
        RandomKeyCoder { prefix, ..self }
    }

    pub fn with_suffix(self, suffix: Vec<u8>) -> RandomKeyCoder<T> {
        RandomKeyCoder { suffix, ..self }
    }
}

impl<T: aes::Encrypter> aes::Encrypter for RandomKeyCoder<T> {
    fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        let mut bb = Vec::clone(&self.prefix);
        bb.extend(plain);
        bb.extend(&self.suffix);

        self.coder.encrypt(&bb)
    }
}

impl<T: aes::Decrypter> aes::Decrypter for RandomKeyCoder<T> {
    fn decrypt(&self, plain: &[u8]) -> Result<Vec<u8>, &str> {
        let mut bb = self.coder.decrypt(plain)?;
        {
            let l = bb.len();
            let pl = self.prefix.len();
            if l > pl && bb[..pl] == self.prefix {
                bb = bb.split_off(pl);
            }
        }

        {
            let l = bb.len();
            let sl = self.suffix.len();
            if l > sl && bb[l - sl..] == self.suffix {
                bb.truncate(l - sl);
            }
        }

        Ok(bb)
    }
}
