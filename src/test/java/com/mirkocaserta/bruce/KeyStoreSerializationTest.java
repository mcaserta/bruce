package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
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

        String encoded = keystoreToString(source, "password", BASE64);
        assertFalse(encoded.isBlank());

        byte[] serialized = Bytes.from(encoded, BASE64).asBytes();
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
}

