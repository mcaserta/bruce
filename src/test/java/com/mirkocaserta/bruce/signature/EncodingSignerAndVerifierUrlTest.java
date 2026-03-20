package com.mirkocaserta.bruce.signature;

import java.security.KeyStore;

import static com.mirkocaserta.bruce.Bruce.Encoding.URL;
import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Bruce.verifierBuilder;
import static com.mirkocaserta.bruce.Keystores.keystore;
import static com.mirkocaserta.bruce.Keystores.privateKey;
import static com.mirkocaserta.bruce.Keystores.publicKey;

class EncodingSignerAndVerifierUrlTest extends EncodingSignerAndVerifierCommonTest {

    @Override
    protected EncodingSigner getSigner() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return signerBuilder().key(privateKey(keystore, "test", "password".toCharArray())).algorithm("SHA512withRSA").encoding(URL).build();
    }

    @Override
    protected EncodingVerifier getVerifier() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return verifierBuilder().key(publicKey(keystore, "test")).algorithm("SHA512withRSA").encoding(URL).build();
    }

}
