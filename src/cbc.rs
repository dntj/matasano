use crate::aes;

pub struct Injector<'a, T: aes::Encrypter> {
  encrypter: &'a T,
}

impl<'a, T: aes::Encrypter> Injector<'a, T> {
  pub fn new(encrypter: &T) -> Injector<T> {
    Injector {
      encrypter: encrypter,
    }
  }

  // inject injects a ciphertext block in the nth block position that decodes to text, given the next plaintext block.
  // text and next must be of size 16.
  pub fn inject(&self, n: usize, text: &str, next: &str) -> Vec<u8> {
    assert_eq!(16, text.len());
    assert_eq!(16, next.len());


    let block = vec![0; 16];
    let mut enc = self.encrypter.encrypt(&block);
    let cur = &enc[n * 16..(n + 1) * 16];

    let mut crafted = Vec::from(text);
    xor(&mut crafted, cur);
    xor(&mut crafted, &Vec::from(next));

    for i in 0..16 {
      enc[n * 16 + i] = crafted[i];
    }

    enc
  }
}

fn xor(x: &mut [u8], y: &[u8]) {
  for i in 0..16 {
    x[i] ^= y[i]
  }
}
