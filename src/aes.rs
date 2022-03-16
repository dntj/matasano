use aes;
use cipher::{BlockDecrypt, BlockEncrypt};
use crypto_common::KeyInit;

pub trait Encrypter {
  fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
}

pub trait Decrypter {
  fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8>;
}

pub struct ECB {
  key: aes::Aes128,
}

impl ECB {
  pub fn new(k: &[u8]) -> Result<ECB, String> {
    let k_res = aes::Aes128::new_from_slice(k);
    if let Err(_) = k_res {
      return Err("bad key".to_string());
    }

    Ok(ECB {
      key: k_res.unwrap(),
    })
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
  fn decrypt(&self, enc: &[u8]) -> Vec<u8> {
    let mut bb = Vec::from(enc);
    for i in 0..(bb.len() / 16) {
      let mut block = aes::Block::from_mut_slice(&mut bb[i * 16..(i + 1) * 16]);
      self.key.decrypt_block(&mut block);
    }

    bb
  }
}

pub struct CBC {
  key: aes::Aes128,
  iv: Vec<u8>,
}

impl CBC {
  pub fn new<'a>(k: &[u8], iv: &[u8]) -> Result<CBC, String> {
    let k_res = aes::Aes128::new_from_slice(k);
    if let Err(_) = k_res {
      return Err("bad key".to_string());
    }
    if iv.len() != 16 {
      return Err("iv must be 16 bytes long".to_string());
    }

    Ok(CBC {
      key: k_res.unwrap(),
      iv: iv.to_owned(),
    })
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
  fn decrypt(&self, enc: &[u8]) -> Vec<u8> {
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

    bb
  }
}

pub fn pad(bb: &[u8], n: usize) -> Vec<u8> {
  let mut padded = Vec::from(bb);

  if bb.len() % n > 0 {
    let diff = n - bb.len() % n;
    padded.extend([4].repeat(diff));
  }

  padded
}
