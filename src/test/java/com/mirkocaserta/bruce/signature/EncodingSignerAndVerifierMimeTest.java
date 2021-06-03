package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Bruce;

import java.security.KeyStore;

import static com.mirkocaserta.bruce.Bruce.*;

class EncodingSignerAndVerifierMimeTest extends EncodingSignerAndVerifierCommonTest {

    @Override
    protected EncodingSigner getSigner() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return signer(privateKey(keystore, "test", "password".toCharArray()), "SHA512withRSA", Bruce.Encoding.MIME);
    }

    @Override
    protected EncodingVerifier getVerifier() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return verifier(publicKey(keystore, "test"), "SHA512withRSA", Bruce.Encoding.MIME);
    }

}
