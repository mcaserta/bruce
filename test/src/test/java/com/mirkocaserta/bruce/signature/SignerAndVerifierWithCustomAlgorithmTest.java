package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;

import com.mirkocaserta.bruce.Bruce;
import java.security.KeyStore;

class SignerAndVerifierWithCustomAlgorithmTest extends SignerAndVerifierCommonTest {

  @Override
  protected Signer getSigner() {
    final KeyStore keystore =
        Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return signer(Bruce.privateKey.with(keystore, "test", "password".toCharArray()), "SHA1withRSA");
  }

  @Override
  protected Verifier getVerifier() {
    final KeyStore keystore =
        Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return verifier(Bruce.publicKey.with(keystore, "test"), "SHA1withRSA");
  }
}
