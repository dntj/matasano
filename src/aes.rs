use aes;
use cipher::{BlockDecrypt, BlockEncrypt};
use crypto_common::KeyInit;

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

  pub fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
    let mut bb = Vec::from(plain);
    for i in 0..(bb.len() / 16) {
      let mut block = aes::Block::from_mut_slice(&mut bb[i * 16..(i + 1) * 16]);
      self.key.encrypt_block(&mut block);
    }

    bb
  }

  pub fn decrypt(&self, enc: &[u8]) -> Vec<u8> {
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

  pub fn encrypt(&self, enc: &[u8]) -> Vec<u8> {
    let mut bb = Vec::from(enc);
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

  pub fn decrypt(&self, enc: &[u8]) -> Vec<u8> {
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
