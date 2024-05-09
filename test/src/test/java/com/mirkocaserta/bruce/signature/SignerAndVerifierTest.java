package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;

import java.security.KeyStore;

class SignerAndVerifierTest extends SignerAndVerifierCommonTest {

  @Override
  protected Signer getSigner() {
    final KeyStore keystore =
        keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return signer(privateKey(keystore, "test", "password".toCharArray()), "SHA512withRSA");
  }

  @Override
  protected Verifier getVerifier() {
    final KeyStore keystore =
        keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return verifier(publicKey(keystore, "test"), "SHA512withRSA");
  }
}