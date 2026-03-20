package com.mirkocaserta.bruce.signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyStore;
import java.security.Security;

import static com.mirkocaserta.bruce.Keystores.keystore;
import static com.mirkocaserta.bruce.Keystores.privateKey;
import static com.mirkocaserta.bruce.Keystores.publicKey;
import static com.mirkocaserta.bruce.Signatures.signer;
import static com.mirkocaserta.bruce.Signatures.verifier;

class SignerAndVerifierWithCustomProviderTest extends SignerAndVerifierCommonTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    protected Signer getSigner() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return signer(privateKey(keystore, "test", "password".toCharArray()), "RIPEMD256withRSA", "BC");
    }

    @Override
    protected Verifier getVerifier() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return verifier(publicKey(keystore, "test"), "RIPEMD256withRSA", "BC");
    }

}
