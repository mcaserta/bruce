package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;

import static com.mirkocaserta.bruce.Bruce.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SignerAndVerifierTest extends SignerAndVerifierCommonTest {

    @Override
    protected Signer getSigner() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        return signer(privateKey(keystore, "test", "password"));
    }

    @Override
    protected Verifier getVerifier() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        return verifier(publicKey(keystore, "test"));
    }

    @Test
    @SuppressWarnings("ResultOfMethodCallIgnored")
    void signerAndVerifiersWithWrongParamsShouldFail() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        assertThrows(BruceException.class, () -> signer(privateKey(keystore, "sgiao belo", "password")));
        assertThrows(BruceException.class, () -> signer(privateKey(keystore, "test", "sgiao belo")));
        assertThrows(BruceException.class, () -> verifier(publicKey(keystore, "sgiao belo")));
    }

}
