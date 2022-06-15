use aes;
use cipher::{BlockDecrypt, BlockEncrypt};
use crypto_common::KeyInit;

pub trait Encrypter {
  fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
}

pub trait Decrypter {
  fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &str>;
}

pub struct ECB {
  key: aes::Aes128,
}

impl ECB {
  pub fn new(k: &[u8]) -> Result<ECB, &'static str> {
    match aes::Aes128::new_from_slice(k) {
      Ok(k) => Ok(ECB { key: k }),
      Err(_) => Err("bad key"),
    }
  }
}

impl Encrypter for ECB {
  fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
    let mut bb = pad(plain, 16);
    for i in 0..(bb.len() / 16) {
      let mut block = aes::Block::from_mut_slice(&mut bb[i * 16..(i + 1) * 16]);
      self.key.encrypt_block(&mut block);
    }

    bb
  }
}

impl Decrypter for ECB {
  fn decrypt(&self, enc: &[u8]) -> Result<Vec<u8>, &str> {
    let mut bb = Vec::from(enc);
    for i in 0..(bb.len() / 16) {
      let mut block = aes::Block::from_mut_slice(&mut bb[i * 16..(i + 1) * 16]);
      self.key.decrypt_block(&mut block);
    }

    unpad(bb)
  }
}

pub struct CBC {
  key: aes::Aes128,
  iv: Vec<u8>,
}

impl CBC {
  pub fn new<'a>(k: &[u8], iv: &[u8]) -> Result<CBC, &'static str> {
    if iv.len() != 16 {
      return Err("iv must be 16 bytes long");
    }

    match aes::Aes128::new_from_slice(k) {
      Ok(k) => Ok(CBC {
        key: k,
        iv: iv.to_owned(),
      }),
      Err(_) => Err("bad key"),
    }
  }
}

impl Encrypter for CBC {
  fn encrypt(&self, enc: &[u8]) -> Vec<u8> {
    let mut bb = pad(enc, 16);
    for i in 0..bb.len() / 16 {
      for j in 0..16 {
        if i == 0 {
          bb[j] ^= self.iv[j];
        } else {
          bb[i * 16 + j] ^= bb[(i - 1) * 16 + j];
        }
      }

      let mut block = aes::Block::from_mut_slice(&mut bb[i * 16..(i + 1) * 16]);
      self.key.encrypt_block(&mut block);
    }

    bb
  }
}

impl Decrypter for CBC {
  fn decrypt(&self, enc: &[u8]) -> Result<Vec<u8>, &str> {
    let mut bb = Vec::from(enc);
    let n = bb.len() / 16;
    for i in 0..n {
      let mut block = aes::Block::from_mut_slice(&mut bb[(n - 1 - i) * 16..(n - i) * 16]);

      self.key.decrypt_block(&mut block);

      for j in 0..16 {
        if i == n - 1 {
          bb[j] ^= self.iv[j];
        } else {
          bb[(n - i - 1) * 16 + j] ^= bb[(n - i - 2) * 16 + j];
        }
      }
    }

    unpad(bb)
  }
}

pub fn pad(bb: &[u8], n: usize) -> Vec<u8> {
  let mut padded = Vec::from(bb);

  if bb.len() % n > 0 {
    let diff = n - bb.len() % n;
    padded.extend([diff as u8].repeat(diff));
  }

  padded
}

pub fn unpad(mut bb: Vec<u8>) -> Result<Vec<u8>, &'static str> {
  let l = bb.len();
  if l == 0 {
    return Ok(bb);
  }

  let last = bb[l - 1];
  if last > 15 {
    return Ok(bb);
  }

  for i in 1..(last as usize) {
    if bb[l - 1 - i] != last {
      return Err("padding error");
    }
  }

  bb.truncate(l - (last as usize));
  Ok(bb)
}
