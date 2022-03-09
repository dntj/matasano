#[cfg(test)]
mod tests {
  use std::fs;
  use std::str;

  use matasano::aes::Coder;
  use matasano::*;

  #[test]
  fn challenge09() {
    assert_eq!(aes::pad(b"YELLOW SUBMARINE", 16), b"YELLOW SUBMARINE");
    assert_eq!(aes::pad(b"YELLOW SUBMARINE", 17), b"YELLOW SUBMARINE\x04");
    assert_eq!(aes::pad(b"YELLOW SUBMARINE", 18), b"YELLOW SUBMARINE\x04\x04");
    assert_eq!(
      aes::pad(b"YELLOW SUBMARINE", 19),
      b"YELLOW SUBMARINE\x04\x04\x04"
    );
    assert_eq!(
      aes::pad(b"YELLOW SUBMARINE", 20),
      b"YELLOW SUBMARINE\x04\x04\x04\x04"
    );
  }

  #[test]
  fn challenge10() {
    let file = fs::read_to_string("tests/data/10.txt").expect("failed to read file");
    let contents = file.replace("\n", "");

    let bb = from_base64(&contents).expect("failed to decode64 contents");

    let iv = [0].repeat(16);
    let k = b"YELLOW SUBMARINE";
    let coder = aes::CBC::new(k, &iv).unwrap();
    let decrypted = coder.decrypt(&bb);

    assert!(str::from_utf8(&decrypted)
      .unwrap()
      .starts_with("I'm back and I'm ringin' the bell"));

    let encrypted = coder.encrypt(&decrypted);
    assert_eq!(encrypted, bb);
  }

  #[test]
  fn challenge11() {
    let file = fs::read_to_string("tests/data/11.txt").expect("failed to read file");

    for _ in 0..10 {
      let res = random_encrypt(file.as_bytes());
      let got = detect_block_mode(&res.ciphertext);

      if res.mode == got {
        return;
      }
    }

    panic!("failed to detect correct block cipher mode in 10 attempts");
  }
}
