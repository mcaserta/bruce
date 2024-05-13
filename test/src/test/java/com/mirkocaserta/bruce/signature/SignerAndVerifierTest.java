package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.api.params.KeyStoreParam.*;

import com.mirkocaserta.bruce.Bruce;

class SignerAndVerifierTest extends SignerAndVerifierCommonTest {

  @Override
  protected Signer getSigner() {
    final var keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"),
            password("password".toCharArray()),
            type("PKCS12"));
    return signer(
        Bruce.privateKey.with(keystore, "test", "password".toCharArray()), "SHA512withRSA");
  }

  @Override
  protected Verifier getVerifier() {
    final var keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"),
            password("password".toCharArray()),
            type("PKCS12"));
    return verifier(Bruce.publicKey.with(keystore, "test"), "SHA512withRSA");
  }
}
