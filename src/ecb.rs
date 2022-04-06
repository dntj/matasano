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
    let pl = self.prefix_len();
    let sl = self.suffix_len();

    let pad = vec![0; 15 * pl % 16];
    let n_pad_blocks = (pl + 15*pl%16)/16;

    while bb.len() < sl {
      let l = bb.len();
      let partial_block = if l < 15 { &bb } else { &bb[l - 15..] };
      let next = self.next_byte(n_pad_blocks, &pad, l, partial_block)?;
      bb.push(next);
    }

    Ok(bb)
  }

  fn prefix_len(&self) -> usize {
    let raw = self.encrypter.encrypt(&[]);
    let shifted = self.encrypter.encrypt(&vec![0; 32]);
    let mut j: usize = 0;
    for i in 0..(raw.len() / 16) {
      if shifted[i * 16..(1 + i) * 16] != raw[i * 16..(i + 1) * 16] {
        j = i + 1;
        break;
      }
    }
    let zero_block = &shifted[j * 16..(j + 1) * 16];

    for i in 0..16 {
      let block = vec![0; 16 + i];
      let e = self.encrypter.encrypt(&block);
      if &e[j * 16..(j + 1) * 16] == zero_block {
        return j * 16 - i;
      }
    }

    (j-1)*16
  }

  fn suffix_len(&self) -> usize {
    let mut min: usize = self.encrypter.encrypt(&[]).len();

    for i in 1..16 {
      let block = vec![0; i];
      let s = self.encrypter.encrypt(&block).len() - i;
      if min == 0 || s < min {
        min = s;
      }
    }

    min - self.prefix_len()
  }

  fn next_byte(&self, n_pad_blocks: usize, pad: &[u8], next_index: usize, bb: &[u8]) -> Result<u8, &str> {
    let block_number = n_pad_blocks + next_index / 16;

    let mut block = Vec::from(pad);
    block.extend(vec![0; 15 - next_index % 16]);
    let ciphertext = self.encrypter.encrypt(&block);
    let want_cipher_block = &ciphertext[block_number * 16..(block_number + 1) * 16];

    for i in 0..=255 {
      let mut block = Vec::from(pad);
      // Populate test block with prefix pad, 15 known values, and the test byte.
      if next_index < 15 {
        block.extend(vec![0; 15 - next_index])
      }
      block.extend(bb);
      block.push(i);

      let cipher = self.encrypter.encrypt(&block);

      let got_cipher_block = &cipher[n_pad_blocks*16..(n_pad_blocks+1)*16];
      if got_cipher_block == want_cipher_block {
        return Ok(i);
      }
    }

    Err("failed to match ciphertext block, not ECB?")
  }
}
