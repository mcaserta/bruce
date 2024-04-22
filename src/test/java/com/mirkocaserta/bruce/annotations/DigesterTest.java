package com.mirkocaserta.bruce.annotations;

import static com.mirkocaserta.bruce.Bruce.instrument;
import static com.mirkocaserta.bruce.digest.DigesterConsts.EMPTY_SHA1;
import static com.mirkocaserta.bruce.digest.DigesterConsts.MESSAGE_SHA1;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Digester annotation tests")
class DigesterTest {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  @DisplayName("Encoding digester for the SHA1 algorithm")
  void encodingDigesterWithDefaults() {
    final var class1 = new Class1();
    instrument(class1);
    assertEquals("b5ua881ui4pzws3O03/p9ZIm4n0=", class1.digest("message"));
    assertEquals("2jmj7l5rSw0yVb/vlWAYkK/YBwk=", class1.digest(""));
  }

  @Test
  @DisplayName("Digester for the SHA1 algorithm")
  void digesterWithDefaults() {
    final var class2 = new Class2();
    instrument(class2);
    assertArrayEquals(MESSAGE_SHA1, class2.digest("message".getBytes(StandardCharsets.UTF_8)));
    assertArrayEquals(EMPTY_SHA1, class2.digest("".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  @DisplayName("Encoding digester for the SHA1 algorithm and all other params set")
  void encodingDigesterWithAllParamsSet() {
    final var class3 = new Class3();
    instrument(class3);
    assertEquals("b5ua881ui4pzws3O03/p9ZIm4n0=", class3.digest("message"));
    assertEquals("2jmj7l5rSw0yVb/vlWAYkK/YBwk=", class3.digest(""));
  }

  @Test
  @DisplayName("Digester for the SHA1 algorithm and a custom provider")
  void digesterWithCustomProvider() {
    final var class4 = new Class4();
    instrument(class4);
    assertArrayEquals(MESSAGE_SHA1, class4.digest("message".getBytes(StandardCharsets.UTF_8)));
    assertArrayEquals(EMPTY_SHA1, class4.digest("".getBytes(StandardCharsets.UTF_8)));
  }

  static class Class1 {
    @SuppressWarnings("unused")
    @Digester(algorithm = "SHA1")
    private com.mirkocaserta.bruce.digest.Digester digester;

    public String digest(String message) {
      return digester.digest(message);
    }
  }

  static class Class2 {
    @SuppressWarnings("unused")
    @Digester(algorithm = "SHA1")
    private com.mirkocaserta.bruce.digest.Digester digester;

    public byte[] digest(byte[] message) {
      return digester.digest(message);
    }
  }

  static class Class3 {
    @SuppressWarnings("unused")
    @Digester(algorithm = "SHA1", provider = "BC", encoding = "BASE64", charsetName = "UTF-8")
    private com.mirkocaserta.bruce.digest.Digester digester;

    public String digest(String message) {
      return digester.digest(message);
    }
  }

  static class Class4 {
    @SuppressWarnings("unused")
    @Digester(algorithm = "SHA1", provider = "BC")
    private com.mirkocaserta.bruce.digest.Digester digester;

    public byte[] digest(byte[] message) {
      return digester.digest(message);
    }
  }
}
