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
    void createEncodingCipherByKeyFailsForMissingKey() {
        var byKey = AsymmetricCipherOperations.createEncodingCipherByKey(
                Map.of("known", privateKey),
                "RSA",
                Bruce.Encoding.BASE64,
                StandardCharsets.UTF_8);

        assertThrows(BruceException.class, () -> byKey.encrypt("missing", Mode.DECRYPT, "abc"));
    }
}

