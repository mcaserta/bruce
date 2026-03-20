package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.PrivateKey;

import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Keystores.keystore;
import static com.mirkocaserta.bruce.Keystores.privateKey;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class SignerAndVerifierExceptionTest {

    @Test
    void noSuchAlgorithm() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        final PrivateKey privateKey = privateKey(keystore, "test", "password".toCharArray());
        assertThrows(BruceException.class, () -> signerBuilder().key(privateKey).algorithm("FOO512withBAR").buildRaw());
    }

    @Test
    void invalidKey() {
        PrivateKey privateKey = mock(PrivateKey.class);
        assertThrows(BruceException.class, () -> signerBuilder().key(privateKey).algorithm("SHA512withRSA").buildRaw());
    }

}
