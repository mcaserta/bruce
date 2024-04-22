package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;

import java.security.KeyStore;

class SignerAndVerifierWithCustomAlgorithmTest extends SignerAndVerifierCommonTest {

  @Override
  protected Signer getSigner() {
    final KeyStore keystore =
        keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return signer(privateKey(keystore, "test", "password".toCharArray()), "SHA1withRSA");
  }

  @Override
  protected Verifier getVerifier() {
    final KeyStore keystore =
        keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return verifier(publicKey(keystore, "test"), "SHA1withRSA");
  }
}
