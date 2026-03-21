package com.mirkocaserta.bruce.impl.cipher;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.cipher.Mode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Map;

import static com.mirkocaserta.bruce.Keystores.keystore;
import static com.mirkocaserta.bruce.Keystores.privateKey;
import static com.mirkocaserta.bruce.Keystores.publicKey;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AsymmetricCipherOperationsTest {

    private final KeyStore keyStore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    private final Key privateKey = privateKey(keyStore, "test", "password".toCharArray());
    private final Key publicKey = publicKey(keyStore, "test");

    @Test
    void modeCannotBeNull() {
        assertThrows(BruceException.class, () -> AsymmetricCipherOperations.createCipher(publicKey, "RSA", (Mode) null));
    }

    @Test
    void createCipherSupportsProviderInstanceBranch() {
        Provider provider = Security.getProviders()[0];
        var cipher = AsymmetricCipherOperations.createCipher(publicKey, "RSA", provider, Mode.ENCRYPT);
        assertNotNull(cipher);
    }

    @Test
    void overloadsWithoutProviderAreUsable() {
        var rawEncrypt = AsymmetricCipherOperations.createCipher(publicKey, "RSA", Mode.ENCRYPT);
        var rawDecrypt = AsymmetricCipherOperations.createCipher(privateKey, "RSA", Mode.DECRYPT);

        byte[] encrypted = rawEncrypt.encrypt("payload".getBytes(StandardCharsets.UTF_8));
        assertNotNull(encrypted);

        byte[] plain = rawDecrypt.encrypt(encrypted);
        assertTrue(new String(plain, StandardCharsets.UTF_8).startsWith("payload"));

        var byKey = AsymmetricCipherOperations.createCipherByKey(Map.of("pub", publicKey, "priv", privateKey), "RSA");
        byte[] encryptedByKey = byKey.encrypt("pub", Mode.ENCRYPT, "hello".getBytes(StandardCharsets.UTF_8));
        assertNotNull(byKey.encrypt("priv", Mode.DECRYPT, encryptedByKey));

        var encodingCipher = AsymmetricCipherOperations.createEncodingCipher(
                publicKey,
                "RSA",
                Mode.ENCRYPT,
                Bruce.Encoding.BASE64,
                StandardCharsets.UTF_8);
        assertNotNull(encodingCipher.encrypt("hello"));
    }

    @Test
    void createEncodingCipherByKeyFailsForMissingKey() {
        var byKey = AsymmetricCipherOperations.createEncodingCipherByKey(
                Map.of("known", privateKey),
                "RSA",
                Bruce.Encoding.BASE64,
                StandardCharsets.UTF_8);

        assertThrows(BruceException.class, () -> byKey.encrypt("missing", Mode.DECRYPT, "abc"));
    }
}

