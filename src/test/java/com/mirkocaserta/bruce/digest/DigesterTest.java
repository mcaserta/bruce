package com.mirkocaserta.bruce.digest;

import static com.mirkocaserta.bruce.digest.DigesterConsts.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.mirkocaserta.bruce.BruceException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Raw digester tests")
class DigesterTest {

  @Test
  @DisplayName("Digester for the SHA1 algorithm")
  void sha1() {
    final var digester = DigesterImpl.with("SHA1", byte[].class);
    assertArrayEquals(MESSAGE_SHA1, digester.apply("message".getBytes(StandardCharsets.UTF_8)));
    assertArrayEquals(EMPTY_SHA1, digester.apply("".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  @DisplayName("Digester for the MD5 algorithm")
  void md5() {
    final var digester = DigesterImpl.with("MD5", byte[].class);
    assertArrayEquals(MESSAGE_MD5, digester.apply("message".getBytes(StandardCharsets.UTF_8)));
    assertArrayEquals(EMPTY_MD5, digester.apply("".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  @DisplayName("Digester for an invalid algorithm should throw a DigesterException")
  void invalidAlgorithm1() {
    Assertions.assertThrows(
        BruceException.class,
        () -> DigesterImpl.with("foo", byte[].class),
        "No such algorithm: foo");
  }

  @Test
  @DisplayName(
      "Digester for an invalid algorithm and invalid provider should throw a DigesterException")
  void invalidAlgorithm2() {
    assertThrows(
        BruceException.class,
        () -> DigesterImpl.with("foo", "bar", byte[].class),
        "No such algorithm: foo");
  }

  @Test
  @DisplayName("Digester for an invalid provider should throw a DigesterException")
  void invalidProvider() {
    assertThrows(
        BruceException.class,
        () -> DigesterImpl.with("SHA1", "foo", byte[].class),
        "No such provider: foo");
  }

  @Test
  @DisplayName("Digester for an invalid encoder should throw a DigesterException")
  void invalidEncoder() {
    assertThrows(
        BruceException.class,
        () -> DigesterImpl.with("SHA1", "SUN", null, null),
        "No such encoding: null");
  }
}
