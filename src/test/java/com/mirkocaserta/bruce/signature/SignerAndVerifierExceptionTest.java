package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.PrivateKey;

import static com.mirkocaserta.bruce.Bruce.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class SignerAndVerifierExceptionTest {

    @Test
    void noSuchAlgorithm() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        final PrivateKey privateKey = privateKey(keystore, "test", "password");
        assertThrows(BruceException.class, () -> signer(privateKey, "FOO512withBAR"));
    }

    @Test
    void invalidKey() {
        PrivateKey privateKey = mock(PrivateKey.class);
        assertThrows(BruceException.class, () -> signer(privateKey, "SHA512withRSA"));
    }

}
