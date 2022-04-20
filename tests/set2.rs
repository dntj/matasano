#[cfg(test)]
mod tests {
  use std::collections::HashMap;
  use std::fs;
  use std::str;

  use matasano::aes::{Decrypter, Encrypter};
  use matasano::ecb;
  use matasano::*;

  #[test]
  fn challenge09() {
    assert_eq!(aes::pad(b"YELLOW SUBMARINE", 16), b"YELLOW SUBMARINE");
    assert_eq!(aes::pad(b"YELLOW SUBMARINE", 17), b"YELLOW SUBMARINE\x01");
    assert_eq!(
      aes::pad(b"YELLOW SUBMARINE", 18),
      b"YELLOW SUBMARINE\x02\x02"
    );
    assert_eq!(
      aes::pad(b"YELLOW SUBMARINE", 19),
      b"YELLOW SUBMARINE\x03\x03\x03"
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
    let decrypted = coder.decrypt(&bb).unwrap();

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
      let res = RandomEncrypter::new(file.as_bytes());
      let got = detect_block_mode(&res.ciphertext);

      if res.mode == got {
        return;
      }
    }

    panic!("failed to detect correct block cipher mode in 10 attempts");
  }

  #[test]
  fn challenge12() {
    let file = fs::read_to_string("tests/data/12.txt").expect("failed to read file");
    let contents = file.replace("\n", "");

    let unknown = from_base64(&contents).unwrap();

    let encrypter = RandomKeyECB::new().with_suffix(unknown);

    let decrypter = ecb::Decrypter::new(&encrypter);

    assert!(str::from_utf8(&decrypter.decrypt().unwrap())
      .unwrap()
      .starts_with("Rollin' in my 5.0"));
  }

  #[test]
  fn challenge13() {
    let ecb = RandomKeyECB::new();

    let enc_profile_for = |email: &str| -> Vec<u8> {
      let mut kvs = Vec::new();
      kvs.push(format!(
        "email={}",
        email.replace("&", "%26").replace("=", "%3D")
      ));
      kvs.push("uid=10".to_string());
      kvs.push("role=user".to_string());

      let encoded = kvs.join("&");
      ecb.encrypt(encoded.as_bytes())
    };

    let decrypt_profile = |ct: &[u8]| -> Result<HashMap<String, String>, std::str::Utf8Error> {
      let dec = ecb.decrypt(ct).unwrap();
      let mut result = HashMap::new();

      for kv in str::from_utf8(&dec)?.split("&") {
        let parts: Vec<&str> = kv.split("=").collect();
        result.insert(
          String::from(parts[0]),
          parts[1].replace("%26", "&").replace("%3D", "="),
        );
      }

      Ok(result)
    };

    // Craft 2nd block with `admin` at start, ending with \x04 padding characters.
    let mut pad = String::from("0000000000admin");
    pad.push_str(str::from_utf8(&[11].repeat(11)).unwrap());
    let admin_block = &enc_profile_for(&pad)[16..32];
    // Craft email with length such that `user` falls into block by itself.
    let mut enc = enc_profile_for("x@example.com");
    enc.truncate(32);
    enc.extend_from_slice(admin_block);

    let profile = decrypt_profile(&enc).unwrap();
    assert_eq!(profile.get("role").unwrap(), "admin");
  }

  #[test]
  fn challenge14() {
    let file = fs::read_to_string("tests/data/12.txt").expect("failed to read file");
    let contents = file.replace("\n", "");

    let unknown = from_base64(&contents).unwrap();

    let encrypter = RandomKeyECB::new()
      .with_random_prefix()
      .with_suffix(unknown);

    let decrypter = ecb::Decrypter::new(&encrypter);

    assert!(str::from_utf8(&decrypter.decrypt().unwrap())
      .unwrap()
      .starts_with("Rollin' in my 5.0"));
  }

  #[test]
  fn challenge15() {
    assert!(aes::unpad(b"YELLOW SUBMARINE\x03".to_vec()).is_err());
    assert!(aes::unpad(b"YELLOW SUBMARINE\x03\x03".to_vec()).is_err());
    assert_eq!(
      aes::unpad(b"YELLOW SUBMARINE\x03\x03\x03".to_vec()).unwrap(),
      b"YELLOW SUBMARINE"
    );
    assert_eq!(
      aes::unpad(b"YELLOW SUBMARINE\x03\x03\x03\x03".to_vec()).unwrap(),
      b"YELLOW SUBMARINE\x03"
    );
  }
}
