#[cfg(test)]
mod tests {
  use std::collections;
  use std::fs;
  use std::str;

  use matasano::*;

  #[test]
  fn challenge1() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(to_base64(&from_hex(hex).unwrap()), base64);
  }

  #[test]
  fn challenge2() {
    let msg = from_hex("1c0111001f010100061a024b53535009181c").unwrap();
    let mask = from_hex("686974207468652062756c6c277320657965").unwrap();
    let want = from_hex("746865206b696420646f6e277420706c6179").unwrap();

    assert_eq!(xor(&msg, &mask), want)
  }

  #[test]
  fn challenge3() {
    let msg =
      from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();

    let r = ScoredXOR::best(&msg);

    // Run test with `cargo test -- --nocapture` to see output.
    assert_eq!(r.result, "Cooking MC's like a pound of bacon")
  }

  #[test]
  fn challenge4() {
    let file = fs::read_to_string("tests/4.txt").expect("failed to read file");

    let mut r: Option<ScoredXOR> = None;
    for s in file.split_ascii_whitespace() {
      let this = ScoredXOR::best(&from_hex(s).expect("bad hex"));
      if r.is_none() || this.score > r.as_ref().unwrap().score {
        r = Some(this);
      }
    }

    assert_eq!(r.unwrap().result, "Now that the party is jumping\n")
  }

  #[test]
  fn challenge5() {
    let line =
      String::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
    let key = String::from("ICE").as_bytes().to_vec();

    let got = to_hex(&xor(&line.as_bytes().to_vec(), &key));

    assert_eq!(
      got,
      String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"),
    );
  }

  #[test]
  fn challenge6() {
    assert_eq!(hamming_distance(&[0], &[0]), 0);
    assert_eq!(hamming_distance(&[0], &[0xff]), 8);
    assert_eq!(hamming_distance(&[0b10101010], &[0b1010101]), 8);
    assert_eq!(hamming_distance(&[0b11110000], &[0b11111111]), 4);
    assert_eq!(
      hamming_distance(&[0b11110000, 1, 2], &[0b11111111, 0, 3]),
      6
    );
    assert_eq!(
      hamming_distance(
        &String::from("this is a test").as_bytes(),
        &String::from("wokka wokka!!!").as_bytes()
      ),
      37
    );

    let file = fs::read_to_string("tests/6.txt").expect("failed to read file");
    let contents = file.replace("\n", "");

    let encrypted = from_base64(&contents).expect("failed to decode64 contents");

    let key = find_key(&encrypted);
    let decrypted = String::from_utf8(xor(&encrypted, &key)).unwrap();

    assert!(decrypted.starts_with("I'm back and I'm ringin' the bell"));
  }

  #[test]
  fn challenge7() {
    let file = fs::read_to_string("tests/7.txt").expect("failed to read file");
    let contents = file.replace("\n", "");

    let bb = from_base64(&contents).expect("failed to decode64 contents");
    let dec = aes128_decrypt_ecb(b"YELLOW SUBMARINE", &bb).unwrap();

    assert!(String::from_utf8(dec).unwrap().starts_with("I'm back and I'm ringin' the bell"));
  }

  #[test]
  fn challenge8() {
    let file = fs::read_to_string("tests/8.txt").expect("failed to read file");

    let mut found = "";
    for s in file.split_ascii_whitespace() {
      let mut counts = collections::HashMap::<&str, u8>::new();
      for i in 0..(s.len() / 32) {
        let k = &s[32 * i..32 * (i + 1)];
        *counts.entry(k).or_default() += 1;
      }
      for (_, v) in &counts {
        if *v > 1 {
          if found != "" {
            panic!("found multiple ECB candidates");
          }
          found = s;
          break;
        }
      }
    }

    assert!(found.starts_with("d880619740a8a19b7840a8a31c810a"));
  }
}
