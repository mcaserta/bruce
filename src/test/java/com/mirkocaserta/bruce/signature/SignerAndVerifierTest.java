package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Crypt;
import com.mirkocaserta.bruce.CryptException;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertThrows;

class SignerAndVerifierTest extends SignerAndVerifierCommonTest {

    @Override
    protected Signer getSigner() {
        final KeyStore keystore = Crypt.keystore("classpath:/keystore.p12", "password", "PKCS12");
        return Crypt.signer(Crypt.privateKey(keystore, "test", "password"));
    }

    @Override
    protected Verifier getVerifier() {
        final KeyStore keystore = Crypt.keystore("classpath:/keystore.p12", "password", "PKCS12");
        return Crypt.verifier(Crypt.publicKey(keystore, "test"));
    }

    @Test
    @SuppressWarnings("ResultOfMethodCallIgnored")
    void signerAndVerifiersWithWrongParamsShouldFail() {
        final KeyStore keystore = Crypt.keystore("classpath:/keystore.p12", "password", "PKCS12");
        assertThrows(CryptException.class, () -> Crypt.signer(Crypt.privateKey(keystore, "sgiao belo", "password")));
        assertThrows(CryptException.class, () -> Crypt.signer(Crypt.privateKey(keystore, "test", "sgiao belo")));
        assertThrows(CryptException.class, () -> Crypt.verifier(Crypt.publicKey(keystore, "sgiao belo")));
    }

}
