package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.Encoding;
import java.security.KeyStore;

class EncodingSignerAndVerifierMimeTest extends EncodingSignerAndVerifierCommonTest {

  @Override
  protected Signer getSigner() {
    final KeyStore keystore =
        Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return signer(
        Bruce.privateKey.with(keystore, "test", "password".toCharArray()),
        "SHA512withRSA",
        Encoding.MIME);
  }

  @Override
  protected Verifier getVerifier() {
    final KeyStore keystore =
        Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return verifier(Bruce.publicKey.with(keystore, "test"), "SHA512withRSA", Encoding.MIME);
  }
}
