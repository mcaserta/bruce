package com.mirkocaserta.bruce.digest;

import com.mirkocaserta.bruce.BruceException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Raw digester tests with custom provider (Bouncy Castle)")
class DigesterWithCustomProviderTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  @DisplayName("Digester for the SHA1 algorithm")
  void sha1() {
    final var digester =
        DigesterImpl.with("SHA1", "BC", byte[].class); // use Bouncy Castle provider
    Assertions.assertArrayEquals(
        DigesterConsts.MESSAGE_SHA1, digester.apply("message".getBytes(StandardCharsets.UTF_8)));
    Assertions.assertArrayEquals(
        DigesterConsts.EMPTY_SHA1, digester.apply("".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  @DisplayName("Digester for the MD5 algorithm")
  void md5() {
    final var digester = DigesterImpl.with("MD5", "BC", byte[].class); // use Bouncy Castle provider
    Assertions.assertArrayEquals(
        DigesterConsts.MESSAGE_MD5, digester.apply("message".getBytes(StandardCharsets.UTF_8)));
    Assertions.assertArrayEquals(
        DigesterConsts.EMPTY_MD5, digester.apply("".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  @DisplayName("Digester for an invalid algorithm should throw a DigesterException")
  void invalidAlgorithm1() {
    Assertions.assertThrows(
        BruceException.class,
        () -> DigesterImpl.with("foo", "BC", byte[].class), // use Bouncy Castle provider
        "No such algorithm: foo");
  }
}
