package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Crypt;
import com.mirkocaserta.bruce.CryptException;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertThrows;

class EncodingSignerAndVerifierBase64Test extends EncodingSignerAndVerifierCommonTest {

    @Override
    protected EncodingSigner getSigner() {
        final KeyStore keystore = Crypt.keystore("classpath:/keystore.p12", "password", "PKCS12");
        return Crypt.encodingSigner(Crypt.privateKey(keystore, "test", "password"), Crypt.Encoding.BASE64);
    }

    @Override
    protected EncodingVerifier getVerifier() {
        final KeyStore keystore = Crypt.keystore("classpath:/keystore.p12", "password", "PKCS12");
        return Crypt.encodingVerifier(Crypt.publicKey(keystore, "test"), Crypt.Encoding.BASE64);
    }

    @Test
    void signerAndVerifiersWithWrongParamsShouldFail() {
        final KeyStore keystore = Crypt.keystore("classpath:/keystore.p12", "password", "PKCS12");
        assertThrows(CryptException.class, () -> Crypt.encodingSigner(Crypt.privateKey(keystore, "sgiao belo", "password"), Crypt.Encoding.BASE64));
        assertThrows(CryptException.class, () -> Crypt.encodingSigner(Crypt.privateKey(keystore, "test", "sgiao belo"), Crypt.Encoding.BASE64));
        assertThrows(CryptException.class, () -> Crypt.encodingVerifier(Crypt.publicKey(keystore, "sgiao belo"), Crypt.Encoding.BASE64));
    }

}
