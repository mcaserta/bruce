package com.mirkocaserta.bruce.impl.digest;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DigestOperationsTest {

    @Test
    void encodingDigesterOverloadsWork() {
        var d1 = DigestOperations.createEncodingDigester("SHA-1", Bruce.Encoding.HEX);
        var d2 = DigestOperations.createEncodingDigester("SHA-1", Bruce.Encoding.HEX, StandardCharsets.UTF_8);
        var d3 = DigestOperations.createEncodingDigester("SHA-1", "", Bruce.Encoding.HEX);

        assertFalse(d1.digest("abc").isBlank());
        assertFalse(d2.digest("abc").isBlank());
        assertFalse(d3.digest("abc").isBlank());
    }

    @Test
    void invalidEncodingAndAlgorithmAreRejected() {
        assertThrows(BruceException.class, () -> DigestOperations.createEncodingDigester("SHA-1", null));
        assertThrows(BruceException.class, () -> DigestOperations.createFileDigester("NO_SUCH_ALG", Bruce.Encoding.HEX));
    }

    @Test
    void missingFileIsReported() {
        var digester = DigestOperations.createFileDigester("SHA-1", Bruce.Encoding.HEX);
        BruceException exception = assertThrows(BruceException.class,
                () -> digester.digest(new File("src/test/resources/definitely-missing-file")));
        assertTrue(exception.getMessage().startsWith("No such file:"));
    }

    @Test
    void rawDigesterOverloadsWork() {
        var d1 = DigestOperations.createRawDigester("SHA-1");
        var d2 = DigestOperations.createRawDigester("SHA-1", "");

        assertArrayEquals(d1.digest("payload".getBytes(StandardCharsets.UTF_8)), d2.digest("payload".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void fileDigesterHandlesEmptyFiles() throws IOException {
        File temp = Files.createTempFile("bruce-empty", ".txt").toFile();
        temp.deleteOnExit();

        var digester = DigestOperations.createFileDigester("SHA-1", Bruce.Encoding.HEX);
        String digest = digester.digest(temp);

        assertFalse(digest.isBlank());
    }
}

