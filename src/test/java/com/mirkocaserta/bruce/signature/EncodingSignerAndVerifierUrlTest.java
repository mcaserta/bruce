package com.mirkocaserta.bruce.signature;

import java.security.KeyStore;

import static com.mirkocaserta.bruce.Bruce.Encoding.URL;
import static com.mirkocaserta.bruce.Bruce.*;

class EncodingSignerAndVerifierUrlTest extends EncodingSignerAndVerifierCommonTest {

    @Override
    protected EncodingSigner getSigner() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        return signer(privateKey(keystore, "test", "password"), "SHA512withRSA", URL);
    }

    @Override
    protected EncodingVerifier getVerifier() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        return verifier(publicKey(keystore, "test"), "SHA512withRSA", URL);
    }

}
