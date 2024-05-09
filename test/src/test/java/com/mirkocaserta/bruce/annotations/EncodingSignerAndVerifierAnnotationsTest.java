package com.mirkocaserta.bruce.annotations;

import static com.mirkocaserta.bruce.Bruce.instrument;

import com.mirkocaserta.bruce.signature.EncodingSignerAndVerifierCommonTest;
import org.junit.jupiter.api.BeforeAll;

class EncodingSignerAndVerifierAnnotationsTest extends EncodingSignerAndVerifierCommonTest {
  private static final Pojo pojo = new Pojo();

  @BeforeAll
  static void beforeAll() {
    instrument(pojo);
  }

  @Override
  protected com.mirkocaserta.bruce.signature.Signer getSigner() {
    return pojo.signer;
  }

  @Override
  protected com.mirkocaserta.bruce.signature.Verifier getVerifier() {
    return pojo.verifier;
  }

  @SuppressWarnings("unused")
  static class Pojo {
    @Verifier(
        publicKey =
            @PublicKey(
                keystore =
                    @KeyStore(
                        location = "classpath:/keystore.p12",
                        password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'},
                        type = "PKCS12"),
                alias = "test"),
        algorithm = "SHA512withRSA")
    private com.mirkocaserta.bruce.signature.Verifier verifier;

    @Signer(
        privateKey =
            @PrivateKey(
                keystore =
                    @KeyStore(
                        location = "classpath:/keystore.p12",
                        password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'},
                        type = "PKCS12"),
                alias = "test",
                password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}),
        algorithm = "SHA512withRSA")
    private com.mirkocaserta.bruce.signature.Signer signer;

    public com.mirkocaserta.bruce.signature.Verifier verifier() {
      return verifier;
    }

    public com.mirkocaserta.bruce.signature.Signer signer() {
      return signer;
    }
  }
}
