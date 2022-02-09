#[cfg(test)]
mod tests {
  use matasano::*;
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
      let msg = from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string()).unwrap();

      let mut max_spaces = -1;
      let mut best :Vec<u8> = vec![];
      for i in 0..=255 {
        let res = xor(&msg, &vec![i]).unwrap();
        let n_spaces = count(&res, String::from(' ').as_bytes()[0]);
        if n_spaces > max_spaces {
          max_spaces = n_spaces;
          best = res;
        }
      }
      // Run test with `cargo test -- --nocapture` to see output.
      println!("Best: {}", str::from_utf8(&best).unwrap());
    }
}
