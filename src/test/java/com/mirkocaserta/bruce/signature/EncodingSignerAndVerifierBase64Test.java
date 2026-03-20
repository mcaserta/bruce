package com.mirkocaserta.bruce.signature;

import java.security.KeyStore;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.Keystores.keystore;
import static com.mirkocaserta.bruce.Keystores.privateKey;
import static com.mirkocaserta.bruce.Keystores.publicKey;
import static com.mirkocaserta.bruce.Signatures.signer;
import static com.mirkocaserta.bruce.Signatures.verifier;

class EncodingSignerAndVerifierBase64Test extends EncodingSignerAndVerifierCommonTest {

    @Override
    protected EncodingSigner getSigner() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return signer(privateKey(keystore, "test", "password".toCharArray()), "SHA512withRSA", BASE64);
    }

    @Override
    protected EncodingVerifier getVerifier() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return verifier(publicKey(keystore, "test"), "SHA512withRSA", BASE64);
    }

}
