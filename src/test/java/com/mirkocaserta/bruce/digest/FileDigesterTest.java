package com.mirkocaserta.bruce.digest;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Encoding;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("File digester tests")
class FileDigesterTest {

  @Test
  @DisplayName("Hexadecimal file digester for the SHA1 algorithm")
  void sha1Hex() {
    final var digester = DigesterImpl.with("SHA1", Encoding.HEX);
    assertEquals(
        "4e1243bd22c66e76c2ba9eddc1f91394e57f9f83",
        digester.apply(new File("src/test/resources/test-file-1")),
        "1st sha1");
    assertEquals(
        "9054fbe0b622c638224d50d20824d2ff6782e308",
        digester.apply(new File("src/test/resources/test-file-2")),
        "2nd sha1");
  }

  @Test
  @DisplayName("Hexadecimal file digester for the SHA1 algorithm with file output")
  void sha1HexWithFileOutput() throws IOException {
    final var digester =
        DigesterImpl.with("SHA1", Encoding.HEX, StandardCharsets.UTF_8, File.class);
    final var file1 = digester.apply(new File("src/test/resources/test-file-1"));
    final var file2 = digester.apply(new File("src/test/resources/test-file-2"));
    assertEquals(
        "4e1243bd22c66e76c2ba9eddc1f91394e57f9f83", Files.readString(file1.toPath()), "1st sha1");
    assertEquals(
        "9054fbe0b622c638224d50d20824d2ff6782e308", Files.readString(file2.toPath()), "2nd sha1");
  }

  @Test
  @DisplayName("Base64 file digester for the SHA1 algorithm")
  void sha1Base64() {
    final var digester = DigesterImpl.with("SHA1", Encoding.BASE64);
    assertEquals(
        "ThJDvSLGbnbCup7dwfkTlOV/n4M=",
        digester.apply(new File("src/test/resources/test-file-1")),
        "1st sha1");
    assertEquals(
        "kFT74LYixjgiTVDSCCTS/2eC4wg=",
        digester.apply(new File("src/test/resources/test-file-2")),
        "2nd sha1");
  }

  @Test
  @DisplayName("Digester for an invalid algorithm should throw a DigesterException")
  void invalidAlgorithm1() {
    Assertions.assertThrows(
        BruceException.class,
        () -> DigesterImpl.with("foo", Encoding.HEX),
        "No such algorithm: foo");
  }
}
