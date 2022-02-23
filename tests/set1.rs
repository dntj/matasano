#[cfg(test)]
mod tests {
  use matasano::*;
  use std::fs;
  use std::str;

  #[test]
  fn challenge1() {
    let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let base64 = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    assert_eq!(to_base64(from_hex(hex).unwrap()), base64);
  }

  #[test]
  fn challenge2() {
    let msg = from_hex("1c0111001f010100061a024b53535009181c".to_string()).unwrap();
    let mask = from_hex("686974207468652062756c6c277320657965".to_string()).unwrap();
    let want = from_hex("746865206b696420646f6e277420706c6179".to_string()).unwrap();

    println!("{}", str::from_utf8(&msg).unwrap());
    println!("{}", str::from_utf8(&mask).unwrap());
    println!("{}", str::from_utf8(&want).unwrap());

    assert_eq!(xor(&msg, &mask).unwrap(), want)
  }

  #[test]
  fn challenge3() {
    let msg =
      from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string())
        .unwrap();

    let r = best_xor(&msg);

    // Run test with `cargo test -- --nocapture` to see output.
    assert_eq!(r.result, "Cooking MC's like a pound of bacon")
  }

  #[test]
  fn challenge4() {
    let contents = fs::read_to_string("tests/4.txt").expect("failed to read file");

    let mut r = Result {
      n_spaces: -1,
      result: String::new(),
    };
    for s in contents.split_ascii_whitespace() {
      let raw = from_hex(s.to_string()).expect("bad hex");
      let this = best_xor(&raw);
      if this.n_spaces > r.n_spaces {
        r.n_spaces = this.n_spaces;
        r.result = this.result;
      }
    }

    println!("Best: {}", r.result);
    assert_eq!(r.result, "Now that the party is jumping\n")
  }
}
