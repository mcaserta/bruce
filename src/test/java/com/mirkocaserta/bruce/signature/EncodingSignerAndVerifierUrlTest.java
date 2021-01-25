package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Crypt;
import com.mirkocaserta.bruce.CryptException;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;

import static com.mirkocaserta.bruce.Crypt.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EncodingSignerAndVerifierUrlTest extends EncodingSignerAndVerifierCommonTest {

    @Override
    protected EncodingSigner getSigner() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        return encodingSigner(privateKey(keystore, "test", "password"), Crypt.Encoding.URL);
    }

    @Override
    protected EncodingVerifier getVerifier() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        return encodingVerifier(publicKey(keystore, "test"), Crypt.Encoding.URL);
    }

    @Test
    void signerAndVerifiersWithWrongParamsShouldFail() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        assertThrows(CryptException.class, () -> encodingSigner(privateKey(keystore, "sgiao belo", "password"), Crypt.Encoding.URL));
        assertThrows(CryptException.class, () -> encodingSigner(privateKey(keystore, "test", "sgiao belo"), Crypt.Encoding.URL));
        assertThrows(CryptException.class, () -> encodingVerifier(publicKey(keystore, "sgiao belo"), Crypt.Encoding.URL));
    }

}
