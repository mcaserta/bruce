package com.mirkocaserta.bruce.signature;

import java.security.KeyStore;

import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Bruce.verifierBuilder;
import static com.mirkocaserta.bruce.Keystores.keystore;
import static com.mirkocaserta.bruce.Keystores.privateKey;
import static com.mirkocaserta.bruce.Keystores.publicKey;

class SignerAndVerifierWithCustomAlgorithmTest extends SignerAndVerifierCommonTest {

    @Override
    protected Signer getSigner() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return signerBuilder().key(privateKey(keystore, "test", "password".toCharArray())).algorithm("SHA1withRSA").buildRaw();
    }

    @Override
    protected Verifier getVerifier() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return verifierBuilder().key(publicKey(keystore, "test")).algorithm("SHA1withRSA").buildRaw();
    }

}
