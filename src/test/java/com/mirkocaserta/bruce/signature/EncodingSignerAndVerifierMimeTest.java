package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;

import com.mirkocaserta.bruce.Bruce;
import java.security.KeyStore;

class EncodingSignerAndVerifierMimeTest extends EncodingSignerAndVerifierCommonTest {

  @Override
  protected Signer getSigner() {
    final KeyStore keystore =
        keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return signer(
        privateKey(keystore, "test", "password".toCharArray()),
        "SHA512withRSA",
        Bruce.Encoding.MIME);
  }

  @Override
  protected Verifier getVerifier() {
    final KeyStore keystore =
        keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return verifier(publicKey(keystore, "test"), "SHA512withRSA", Bruce.Encoding.MIME);
  }
}
