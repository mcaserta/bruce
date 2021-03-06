package com.mirkocaserta.bruce.digest;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static com.mirkocaserta.bruce.Bruce.digester;
import static com.mirkocaserta.bruce.digest.DigesterConsts.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("Raw digester tests")
class DigesterTest {

    @Test
    @DisplayName("Digester for the SHA1 algorithm")
    void sha1() {
        Digester digester = digester("SHA1");
        assertArrayEquals(MESSAGE_SHA1, digester.digest("message".getBytes(StandardCharsets.UTF_8)));
        assertArrayEquals(EMPTY_SHA1, digester.digest("".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    @DisplayName("Digester for the MD5 algorithm")
    void md5() {
        Digester digester = digester("MD5");
        assertArrayEquals(MESSAGE_MD5, digester.digest("message".getBytes(StandardCharsets.UTF_8)));
        assertArrayEquals(EMPTY_MD5, digester.digest("".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    @DisplayName("Digester for an invalid algorithm should throw a DigesterException")
    void invalidAlgorithm1() {
        Assertions.assertThrows(
                BruceException.class,
                () -> digester("foo"),
                "No such algorithm: foo"
        );
    }

    @Test
    @DisplayName("Digester for an invalid algorithm and invalid provider should throw a DigesterException")
    void invalidAlgorithm2() {
        assertThrows(
                BruceException.class,
                () -> digester("foo", "bar"),
                "No such algorithm: foo"
        );
    }

    @Test
    @DisplayName("Digester for an invalid provider should throw a DigesterException")
    void invalidProvider() {
        assertThrows(
                BruceException.class,
                () -> digester("SHA1", "foo"),
                "No such provider: foo"
        );
    }

    @Test
    @DisplayName("Digester for an invalid encoder should throw a DigesterException")
    void invalidEncoder() {
        assertThrows(
                BruceException.class,
                () -> digester("SHA1", "SUN", null),
                "No such encoding: null"
        );
    }

}