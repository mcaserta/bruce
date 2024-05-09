package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;

import java.security.KeyStore;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

class SignerAndVerifierWithCustomProviderTest extends SignerAndVerifierCommonTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Override
  protected Signer getSigner() {
    final KeyStore keystore =
        keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return signer(privateKey(keystore, "test", "password".toCharArray()), "RIPEMD256withRSA", "BC");
  }

  @Override
  protected Verifier getVerifier() {
    final KeyStore keystore =
        keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return verifier(publicKey(keystore, "test"), "RIPEMD256withRSA", "BC");
  }
}