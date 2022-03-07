#[cfg(test)]
mod tests {

  use matasano::*;

  #[test]
  fn challenge9() {
    assert_eq!(pad(b"YELLOW SUBMARINE", 16, 0), b"YELLOW SUBMARINE");
    assert_eq!(pad(b"YELLOW SUBMARINE", 17, 1), b"YELLOW SUBMARINE\x01");
    assert_eq!(pad(b"YELLOW SUBMARINE", 18, 2), b"YELLOW SUBMARINE\x02\x02");
    assert_eq!(pad(b"YELLOW SUBMARINE", 19, 3), b"YELLOW SUBMARINE\x03\x03\x03");
    assert_eq!(pad(b"YELLOW SUBMARINE", 20, 4), b"YELLOW SUBMARINE\x04\x04\x04\x04");
  }
}