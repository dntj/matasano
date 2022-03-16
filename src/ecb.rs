use std::collections;
use std::convert::TryInto;

use crate::aes;

pub struct Decrypter<'a> {
  encrypter: &'a dyn aes::Encrypter,
  len: usize,
}

impl<'a> Decrypter<'a> {
  pub fn new(encrypter: &'a dyn aes::Encrypter) -> Decrypter {
    let mut min: usize = encrypter.encrypt(&[]).len();

    for i in 1..16 {
      let block = vec![0; i];
      let s = encrypter.encrypt(&block).len() - i;
      if min == 0 || s < min {
        min = s;
      }
    }

    Decrypter {
      encrypter: encrypter,
      len: min,
    }
  }

  pub fn decrypt(&self) -> Vec<u8> {
    let mut bb = Vec::<u8>::new();

    while bb.len() < self.len {
      self.calc_next_byte(&mut bb);
    }

    bb
  }

  pub fn calc_next_byte(&self, bb: &mut Vec<u8>) {
    let mut cipher_map = collections::HashMap::<[u8; 16], [u8; 16]>::new();
    let l = bb.len();

    for i in 0..=255 {
      let mut block: [u8; 16] = [0; 16];
      for j in 0..15 {
        if l + j >= 15 {
          block[j] = bb[l + j - 15];
        }
      }
      block[15] = i;
      let cipher_block = self.encrypter.encrypt(&block);
      cipher_map.insert(cipher_block[..16].try_into().unwrap(), block);
    }

    let partial = vec![0; 15 - l % 16];
    let ciphertext = self.encrypter.encrypt(&partial);

    let d = bb.len() / 16;
    let plain = cipher_map.get::<[u8; 16]>(ciphertext[d * 16..(d + 1) * 16].try_into().unwrap());

    bb.push(plain.unwrap()[15]);
  }
}
