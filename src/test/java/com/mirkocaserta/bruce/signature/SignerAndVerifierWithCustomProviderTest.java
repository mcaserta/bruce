package com.mirkocaserta.bruce.signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyStore;
import java.security.Security;

import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Bruce.verifierBuilder;
import static com.mirkocaserta.bruce.Keystores.keystore;
import static com.mirkocaserta.bruce.Keystores.privateKey;
import static com.mirkocaserta.bruce.Keystores.publicKey;

class SignerAndVerifierWithCustomProviderTest extends SignerAndVerifierCommonTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    protected Signer getSigner() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return signerBuilder().key(privateKey(keystore, "test", "password".toCharArray())).algorithm("RIPEMD256withRSA").provider("BC").buildRaw();
    }

    @Override
    protected Verifier getVerifier() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        return verifierBuilder().key(publicKey(keystore, "test")).algorithm("RIPEMD256withRSA").provider("BC").buildRaw();
    }

}
