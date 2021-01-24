package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Crypt;

import java.security.KeyStore;

class SignerAndVerifierWithCustomAlgorithmTest extends SignerAndVerifierCommonTest {

    @Override
    protected Signer getSigner() {
        final KeyStore keystore = Crypt.keystore("classpath:/keystore.p12", "password", "PKCS12");
        return Crypt.signer(Crypt.privateKey(keystore, "test", "password"), "SHA1withRSA");
    }

    @Override
    protected Verifier getVerifier() {
        final KeyStore keystore = Crypt.keystore("classpath:/keystore.p12", "password", "PKCS12");
        return Crypt.verifier(Crypt.publicKey(keystore, "test"), "SHA1withRSA");
    }

}
