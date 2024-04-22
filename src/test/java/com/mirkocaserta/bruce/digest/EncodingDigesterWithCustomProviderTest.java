package com.mirkocaserta.bruce.digest;

import static com.mirkocaserta.bruce.Bruce.digester;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.mirkocaserta.bruce.BruceException;
import java.security.Security;

import com.mirkocaserta.bruce.Encoding;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Encoding digester tests with custom provider (Bouncy Castle)")
class EncodingDigesterWithCustomProviderTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  @DisplayName("Hexadecimal digester for the SHA1 algorithm")
  void sha1Hex() {
    final var digester = digester("SHA1", "BC", Encoding.HEX); // use Bouncy Castle provider
    assertEquals(
        "6f9b9af3cd6e8b8a73c2cdced37fe9f59226e27d", digester.digest("message"), "1st sha1");
    assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", digester.digest(""), "2nd sha1");
  }

  @Test
  @DisplayName("Base64 encoding digester for the SHA1 algorithm")
  void sha1Base64() {
    final var digester = digester("SHA1", "BC", Encoding.BASE64); // use Bouncy Castle provider
    assertEquals("b5ua881ui4pzws3O03/p9ZIm4n0=", digester.digest("message"), "1st sha1");
    assertEquals("2jmj7l5rSw0yVb/vlWAYkK/YBwk=", digester.digest(""), "2nd sha1");
  }

  @Test
  @DisplayName("Url encoding digester for the SHA1 algorithm")
  void sha1Url() {
    final var digester = digester("SHA1", "BC", Encoding.URL); // use Bouncy Castle provider
    assertEquals("b5ua881ui4pzws3O03_p9ZIm4n0=", digester.digest("message"), "1st sha1");
    assertEquals("2jmj7l5rSw0yVb_vlWAYkK_YBwk=", digester.digest(""), "2nd sha1");
  }

  @Test
  @DisplayName("MIME encoding digester for the SHA1 algorithm")
  void sha1MIME() {
    final var digester = digester("SHA1", "BC", Encoding.MIME); // use Bouncy Castle provider
    assertEquals("b5ua881ui4pzws3O03/p9ZIm4n0=", digester.digest("message"), "1st sha1");
    assertEquals("2jmj7l5rSw0yVb/vlWAYkK/YBwk=", digester.digest(""), "2nd sha1");
  }

  @Test
  @DisplayName("Hexadecimal digester for the MD5 algorithm")
  void md5Hex() {
    final var digester = digester("MD5", "BC", Encoding.HEX); // use Bouncy Castle provider
    assertEquals("78e731027d8fd50ed642340b7c9a63b3", digester.digest("message"), "1st md5");
    assertEquals("d41d8cd98f00b204e9800998ecf8427e", digester.digest(""), "2nd md5");
  }

  @Test
  @DisplayName("Base64 encoding digester for the MD5 algorithm")
  void md5Base64() {
    final var digester = digester("MD5", "BC", Encoding.BASE64); // use Bouncy Castle provider
    assertEquals("eOcxAn2P1Q7WQjQLfJpjsw==", digester.digest("message"), "1st md5");
    assertEquals("1B2M2Y8AsgTpgAmY7PhCfg==", digester.digest(""), "2nd md5");
  }

  @Test
  @DisplayName("Url encoding digester for the MD5 algorithm")
  void md5Url() {
    final var digester = digester("MD5", "BC", Encoding.URL); // use Bouncy Castle provider
    assertEquals("eOcxAn2P1Q7WQjQLfJpjsw==", digester.digest("message"), "1st md5");
    assertEquals("1B2M2Y8AsgTpgAmY7PhCfg==", digester.digest(""), "2nd md5");
  }

  @Test
  @DisplayName("Mime encoding digester for the MD5 algorithm")
  void md5MIME() {
    final var digester = digester("MD5", "BC", Encoding.MIME); // use Bouncy Castle provider
    assertEquals("eOcxAn2P1Q7WQjQLfJpjsw==", digester.digest("message"), "1st md5");
    assertEquals("1B2M2Y8AsgTpgAmY7PhCfg==", digester.digest(""), "2nd md5");
  }

  @Test
  @DisplayName("Digester for an invalid algorithm should throw a DigesterException")
  void invalidAlgorithm1() {
    Assertions.assertThrows(
        BruceException.class,
        () -> digester("foo", "BC", Encoding.HEX), // use Bouncy Castle provider
        "No such algorithm: foo");
  }
}
