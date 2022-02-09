#[cfg(test)]
mod tests {
    #[test]
    fn challenge1() {
      let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
      let base64 = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

      match matasano::from_hex(hex) {
        Ok(bb) => assert_eq!(matasano::to_base64(bb), base64),
        Err(err) => panic!("{}", err),
      }
    }
}
