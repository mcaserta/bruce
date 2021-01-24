package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Crypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyStore;
import java.security.Security;

class SignerAndVerifierWithCustomProviderTest extends SignerAndVerifierCommonTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    protected Signer getSigner() {
        final KeyStore keystore = Crypt.keystore("classpath:/keystore.p12", "password", "PKCS12");
        return Crypt.signer(Crypt.privateKey(keystore, "test", "password"), "RIPEMD256withRSA", "BC");
    }

    @Override
    protected Verifier getVerifier() {
        final KeyStore keystore = Crypt.keystore("classpath:/keystore.p12", "password", "PKCS12");
        return Crypt.verifier(Crypt.publicKey(keystore, "test"), "RIPEMD256withRSA", "BC");
    }

}
