package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.Encoding.BASE64;

import com.mirkocaserta.bruce.Bruce;
import java.security.KeyStore;

class EncodingSignerAndVerifierBase64Test extends EncodingSignerAndVerifierCommonTest {

  @Override
  protected Signer getSigner() {
    final KeyStore keystore =
        Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return signer(privateKey(keystore, "test", "password".toCharArray()), "SHA512withRSA", BASE64);
  }

  @Override
  protected Verifier getVerifier() {
    final KeyStore keystore =
        Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return verifier(publicKey(keystore, "test"), "SHA512withRSA", BASE64);
  }
}
