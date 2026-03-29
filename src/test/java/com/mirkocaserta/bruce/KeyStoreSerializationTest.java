package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.mirkocaserta.bruce.Keystores.certificate;
import static com.mirkocaserta.bruce.Keystores.keystore;
import static com.mirkocaserta.bruce.Keystores.keystoreToBytes;
import static com.mirkocaserta.bruce.Keystores.keystoreToFile;
import static com.mirkocaserta.bruce.Keystores.keystoreToString;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyStoreSerializationTest {

    @Test
    void serializesKeystoreToByteArrayAndRoundTrips() throws Exception {
        var source = keystore("classpath:/keystore-alice.p12", "password");

        byte[] serialized = keystoreToBytes(source, "password");
        assertTrue(serialized.length > 0);

        Path temp = Files.createTempFile("bruce-keystore-bytes-", ".p12");
        Files.write(temp, serialized);

        var reloaded = keystore(temp.toUri().toString(), "password", "PKCS12");
        assertNotNull(certificate(reloaded, "alice"));

        Files.deleteIfExists(temp);
    }

    @Test
    void serializesKeystoreToEncodedStringAndRoundTrips() throws Exception {
        var source = keystore("classpath:/keystore-alice.p12", "password");

        String encoded = keystoreToString(source, "password", Bruce.Encoding.BASE64);
        assertFalse(encoded.isBlank());

        byte[] serialized = Bytes.from(encoded, Bruce.Encoding.BASE64).asBytes();
        Path temp = Files.createTempFile("bruce-keystore-string-", ".p12");
        Files.write(temp, serialized);

        var reloaded = keystore(temp.toUri().toString(), "password", "PKCS12");
        assertNotNull(certificate(reloaded, "alice"));

        Files.deleteIfExists(temp);
    }

    @Test
    void serializesKeystoreDirectlyToFile() throws Exception {
        var source = keystore("classpath:/keystore-alice.p12", "password");

        Path temp = Files.createTempFile("bruce-keystore-file-", ".p12");
        keystoreToFile(source, "password", temp);

        assertTrue(Files.size(temp) > 0);

        var reloaded = keystore(temp.toUri().toString(), "password", "PKCS12");
        assertNotNull(certificate(reloaded, "alice"));

        Files.deleteIfExists(temp);
    }

    @ParameterizedTest
    @EnumSource(Bruce.Encoding.class)
    void serializesKeystoreToAllSupportedEncodings(Bruce.Encoding encoding) throws Exception {
        var source = keystore("classpath:/keystore-alice.p12", "password");

        String encoded = keystoreToString(source, "password", encoding);
        assertFalse(encoded.isBlank());

        byte[] serialized = Bytes.from(encoded, encoding).asBytes();
        Path temp = Files.createTempFile("bruce-keystore-encoding-", ".p12");
        Files.write(temp, serialized);

        var reloaded = keystore(temp.toUri().toString(), "password", "PKCS12");
        assertNotNull(certificate(reloaded, "alice"));

        Files.deleteIfExists(temp);
    }

    @Test
    void stringAndCharArrayOverloadsProduceEquivalentOutputs() throws Exception {
        var source = keystore("classpath:/keystore-alice.p12", "password");

        byte[] fromStringPassword = keystoreToBytes(source, "password");
        byte[] fromCharArrayPassword = keystoreToBytes(source, "password".toCharArray());
        assertTrue(fromStringPassword.length > 0);
        assertTrue(fromCharArrayPassword.length > 0);

        String encodedString = keystoreToString(source, "password", Bruce.Encoding.BASE64);
        String encodedCharArray = keystoreToString(source, "password".toCharArray(), Bruce.Encoding.BASE64);
        assertFalse(encodedString.isBlank());
        assertFalse(encodedCharArray.isBlank());

        Path fromStringEncoded = Files.createTempFile("bruce-keystore-string-overload-a-", ".p12");
        Path fromCharEncoded = Files.createTempFile("bruce-keystore-string-overload-b-", ".p12");
        Files.write(fromStringEncoded, Bytes.from(encodedString, Bruce.Encoding.BASE64).asBytes());
        Files.write(fromCharEncoded, Bytes.from(encodedCharArray, Bruce.Encoding.BASE64).asBytes());

        var reloadFromStringEncoded = keystore(fromStringEncoded.toUri().toString(), "password", "PKCS12");
        var reloadFromCharEncoded = keystore(fromCharEncoded.toUri().toString(), "password", "PKCS12");
        assertNotNull(certificate(reloadFromStringEncoded, "alice"));
        assertNotNull(certificate(reloadFromCharEncoded, "alice"));

        Path pathOutput = Files.createTempFile("bruce-keystore-path-", ".p12");
        Path fileOutput = Files.createTempFile("bruce-keystore-file-", ".p12");
        keystoreToFile(source, "password".toCharArray(), pathOutput);
        keystoreToFile(source, "password", fileOutput.toFile());

        assertTrue(Files.size(pathOutput) > 0);
        assertTrue(Files.size(fileOutput) > 0);

        var reloadedPath = keystore(pathOutput.toUri().toString(), "password", "PKCS12");
        var reloadedFile = keystore(fileOutput.toUri().toString(), "password", "PKCS12");
        assertNotNull(certificate(reloadedPath, "alice"));
        assertNotNull(certificate(reloadedFile, "alice"));

        Files.deleteIfExists(fromStringEncoded);
        Files.deleteIfExists(fromCharEncoded);

        Files.deleteIfExists(pathOutput);
        Files.deleteIfExists(fileOutput);
    }

    @Test
    void fileOverloadsWriteReadableKeystores() throws Exception {
        var source = keystore("classpath:/keystore-alice.p12", "password");

        File fileA = Files.createTempFile("bruce-keystore-overload-a-", ".p12").toFile();
        File fileB = Files.createTempFile("bruce-keystore-overload-b-", ".p12").toFile();

        keystoreToFile(source, "password".toCharArray(), fileA);
        keystoreToFile(source, "password", fileB);

        var reloadedA = keystore(fileA.toURI().toString(), "password", "PKCS12");
        var reloadedB = keystore(fileB.toURI().toString(), "password", "PKCS12");
        assertNotNull(certificate(reloadedA, "alice"));
        assertNotNull(certificate(reloadedB, "alice"));

        Files.deleteIfExists(fileA.toPath());
        Files.deleteIfExists(fileB.toPath());
    }
}

