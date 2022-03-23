use crate::aes;

pub struct Decrypter<'a> {
  encrypter: &'a dyn aes::Encrypter,
}

impl<'a> Decrypter<'a> {
  pub fn new(encrypter: &'a dyn aes::Encrypter) -> Decrypter {
    Decrypter {
      encrypter: encrypter,
    }
  }

  pub fn decrypt(&self) -> Result<Vec<u8>, &str> {
    let mut bb = Vec::<u8>::new();

    while bb.len() < self.len() {
      let l = bb.len();
      let partial_block = if l < 15 { &bb } else { &bb[l - 15..] };
      let next = self.next_byte(l, partial_block)?;
      bb.push(next);
    }

    Ok(bb)
  }

  fn len(&self) -> usize {
    let mut min: usize = self.encrypter.encrypt(&[]).len();

    for i in 1..16 {
      let block = vec![0; i];
      let s = self.encrypter.encrypt(&block).len() - i;
      if min == 0 || s < min {
        min = s;
      }
    }

    min
  }

  fn next_byte(&self, next_index: usize, bb: &[u8]) -> Result<u8, &str> {
    let block_number = next_index / 16;

    let ciphertext = self.encrypter.encrypt(&vec![0; 15 - next_index % 16]);
    let want_cipher_block = &ciphertext[block_number * 16..(block_number + 1) * 16];

    for i in 0..=255 {
      // Populate test block with 15 known values, and the test byte.
      let mut block = if next_index < 15 {
        vec![0; 15 - next_index]
      } else {
        Vec::new()
      };
      block.extend(bb);
      block.push(i);

      let cipher = self.encrypter.encrypt(&block);

      let got_cipher_block = &cipher[..16];
      if got_cipher_block == want_cipher_block {
        return Ok(i);
      }
    }

    Err("failed to match ciphertext block, not ECB?")
  }
}
