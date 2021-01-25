package com.mirkocaserta.bruce.digest;

import com.mirkocaserta.bruce.Crypt;
import com.mirkocaserta.bruce.CryptException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.mirkocaserta.bruce.Crypt.digester;
import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("Encoding digester tests")
class EncodingDigesterTest {

    @Test
    @DisplayName("Hexadecimal digester for the SHA1 algorithm")
    void sha1Hex() {
        EncodingDigester digester = digester("SHA1", Crypt.Encoding.HEX);
        assertEquals("6f9b9af3cd6e8b8a73c2cdced37fe9f59226e27d", digester.digest("message"), "1st sha1");
        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", digester.digest(""), "2nd sha1");
    }

    @Test
    @DisplayName("Base64 encoding digester for the SHA1 algorithm")
    void sha1Base64() {
        EncodingDigester digester = digester("SHA1", Crypt.Encoding.BASE64);
        assertEquals("b5ua881ui4pzws3O03/p9ZIm4n0=", digester.digest("message"), "1st sha1");
        assertEquals("2jmj7l5rSw0yVb/vlWAYkK/YBwk=", digester.digest(""), "2nd sha1");
    }

    @Test
    @DisplayName("Url encoding digester for the SHA1 algorithm")
    void sha1Url() {
        EncodingDigester digester = digester("SHA1", Crypt.Encoding.URL);
        assertEquals("b5ua881ui4pzws3O03_p9ZIm4n0=", digester.digest("message"), "1st sha1");
        assertEquals("2jmj7l5rSw0yVb_vlWAYkK_YBwk=", digester.digest(""), "2nd sha1");
    }

    @Test
    @DisplayName("MIME encoding digester for the SHA1 algorithm")
    void sha1MIME() {
        EncodingDigester digester = digester("SHA1", Crypt.Encoding.MIME);
        assertEquals("b5ua881ui4pzws3O03/p9ZIm4n0=", digester.digest("message"), "1st sha1");
        assertEquals("2jmj7l5rSw0yVb/vlWAYkK/YBwk=", digester.digest(""), "2nd sha1");
    }

    @Test
    @DisplayName("Hexadecimal digester for the MD5 algorithm")
    void md5Hex() {
        EncodingDigester digester = digester("MD5", Crypt.Encoding.HEX);
        assertEquals("78e731027d8fd50ed642340b7c9a63b3", digester.digest("message"), "1st md5");
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", digester.digest(""), "2nd md5");
    }

    @Test
    @DisplayName("Base64 encoding digester for the MD5 algorithm")
    void md5Base64() {
        EncodingDigester digester = digester("MD5", Crypt.Encoding.BASE64);
        assertEquals("eOcxAn2P1Q7WQjQLfJpjsw==", digester.digest("message"), "1st md5");
        assertEquals("1B2M2Y8AsgTpgAmY7PhCfg==", digester.digest(""), "2nd md5");
    }

    @Test
    @DisplayName("Url encoding digester for the MD5 algorithm")
    void md5Url() {
        EncodingDigester digester = digester("MD5", Crypt.Encoding.URL);
        assertEquals("eOcxAn2P1Q7WQjQLfJpjsw==", digester.digest("message"), "1st md5");
        assertEquals("1B2M2Y8AsgTpgAmY7PhCfg==", digester.digest(""), "2nd md5");
    }

    @Test
    @DisplayName("Mime encoding digester for the MD5 algorithm")
    void md5MIME() {
        EncodingDigester digester = digester("MD5", Crypt.Encoding.MIME);
        assertEquals("eOcxAn2P1Q7WQjQLfJpjsw==", digester.digest("message"), "1st md5");
        assertEquals("1B2M2Y8AsgTpgAmY7PhCfg==", digester.digest(""), "2nd md5");
    }

    @Test
    @DisplayName("Digester for an invalid algorithm should throw a DigesterException")
    void invalidAlgorithm1() {
        Assertions.assertThrows(
                CryptException.class,
                () -> digester("foo", Crypt.Encoding.HEX),
                "No such algorithm: foo"
        );
    }

}