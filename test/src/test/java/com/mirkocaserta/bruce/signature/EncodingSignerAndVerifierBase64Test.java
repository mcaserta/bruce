package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.api.KeyStoreParam.*;

import com.mirkocaserta.bruce.Bruce;

class EncodingSignerAndVerifierBase64Test extends EncodingSignerAndVerifierCommonTest {

  @Override
  protected Signer getSigner() {
    final var keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"),
            password("password".toCharArray()),
            type("PKCS12"));
    return signer(
        Bruce.privateKey.with(keystore, "test", "password".toCharArray()), "SHA512withRSA", BASE64);
  }

  @Override
  protected Verifier getVerifier() {
    final var keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"),
            password("password".toCharArray()),
            type("PKCS12"));
    return verifier(Bruce.publicKey.with(keystore, "test"), "SHA512withRSA", BASE64);
  }
}
