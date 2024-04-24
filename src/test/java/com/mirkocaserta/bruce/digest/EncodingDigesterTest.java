package com.mirkocaserta.bruce.digest;

import static com.mirkocaserta.bruce.Bruce.digester;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Encoding;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Encoding digester tests")
class EncodingDigesterTest {

  @Test
  @DisplayName("Hexadecimal digester for the SHA1 algorithm")
  void sha1Hex() {
    final var digester = digester("SHA1", Encoding.HEX);
    assertEquals("6f9b9af3cd6e8b8a73c2cdced37fe9f59226e27d", digester.apply("message"), "1st sha1");
    assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", digester.apply(""), "2nd sha1");
  }

  @Test
  @DisplayName("Base64 encoding digester for the SHA1 algorithm")
  void sha1Base64() {
    final var digester = digester("SHA1", Encoding.BASE64);
    assertEquals("b5ua881ui4pzws3O03/p9ZIm4n0=", digester.apply("message"), "1st sha1");
    assertEquals("2jmj7l5rSw0yVb/vlWAYkK/YBwk=", digester.apply(""), "2nd sha1");
  }

  @Test
  @DisplayName("Url encoding digester for the SHA1 algorithm")
  void sha1Url() {
    final var digester = digester("SHA1", Encoding.URL);
    assertEquals("b5ua881ui4pzws3O03_p9ZIm4n0=", digester.apply("message"), "1st sha1");
    assertEquals("2jmj7l5rSw0yVb_vlWAYkK_YBwk=", digester.apply(""), "2nd sha1");
  }

  @Test
  @DisplayName("MIME encoding digester for the SHA1 algorithm")
  void sha1MIME() {
    final var digester = digester("SHA1", Encoding.MIME);
    assertEquals("b5ua881ui4pzws3O03/p9ZIm4n0=", digester.apply("message"), "1st sha1");
    assertEquals("2jmj7l5rSw0yVb/vlWAYkK/YBwk=", digester.apply(""), "2nd sha1");
  }

  @Test
  @DisplayName("Hexadecimal digester for the MD5 algorithm")
  void md5Hex() {
    final var digester = digester("MD5", Encoding.HEX);
    assertEquals("78e731027d8fd50ed642340b7c9a63b3", digester.apply("message"), "1st md5");
    assertEquals("d41d8cd98f00b204e9800998ecf8427e", digester.apply(""), "2nd md5");
  }

  @Test
  @DisplayName("Base64 encoding digester for the MD5 algorithm")
  void md5Base64() {
    final var digester = digester("MD5", Encoding.BASE64);
    assertEquals("eOcxAn2P1Q7WQjQLfJpjsw==", digester.apply("message"), "1st md5");
    assertEquals("1B2M2Y8AsgTpgAmY7PhCfg==", digester.apply(""), "2nd md5");
  }

  @Test
  @DisplayName("Url encoding digester for the MD5 algorithm")
  void md5Url() {
    final var digester = digester("MD5", Encoding.URL);
    assertEquals("eOcxAn2P1Q7WQjQLfJpjsw==", digester.apply("message"), "1st md5");
    assertEquals("1B2M2Y8AsgTpgAmY7PhCfg==", digester.apply(""), "2nd md5");
  }

  @Test
  @DisplayName("Mime encoding digester for the MD5 algorithm")
  void md5MIME() {
    final var digester = digester("MD5", Encoding.MIME);
    assertEquals("eOcxAn2P1Q7WQjQLfJpjsw==", digester.apply("message"), "1st md5");
    assertEquals("1B2M2Y8AsgTpgAmY7PhCfg==", digester.apply(""), "2nd md5");
  }

  @Test
  @DisplayName("Digester for an invalid algorithm should throw a DigesterException")
  void invalidAlgorithm1() {
    Assertions.assertThrows(
        BruceException.class, () -> digester("foo", Encoding.HEX), "No such algorithm: foo");
  }
}
