package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.Encoding.HEX;

import com.mirkocaserta.bruce.Bruce;
import java.security.KeyStore;

class EncodingSignerAndVerifierHexTest extends EncodingSignerAndVerifierCommonTest {

  @Override
  protected Signer getSigner() {
    final KeyStore keystore =
        Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return signer(privateKey(keystore, "test", "password".toCharArray()), "SHA512withRSA", HEX);
  }

  @Override
  protected Verifier getVerifier() {
    final KeyStore keystore =
        Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    return verifier(publicKey(keystore, "test"), "SHA512withRSA", HEX);
  }
}
