package com.mirkocaserta.bruce.annotations;

import com.mirkocaserta.bruce.signature.EncodingSigner;
import com.mirkocaserta.bruce.signature.EncodingSignerAndVerifierCommonTest;
import com.mirkocaserta.bruce.signature.EncodingVerifier;
import org.junit.jupiter.api.BeforeAll;

import static com.mirkocaserta.bruce.Bruce.instrument;

class EncodingSignerAndVerifierAnnotationsTest extends EncodingSignerAndVerifierCommonTest {
    private static final Pojo pojo = new Pojo();

    @BeforeAll
    static void beforeAll() {
        instrument(pojo);
    }

    @Override
    protected EncodingSigner getSigner() {
        return pojo.signer;
    }

    @Override
    protected EncodingVerifier getVerifier() {
        return pojo.verifier;
    }

    @SuppressWarnings("unused")
    static class Pojo {
        @Verifier(publicKey = @PublicKey(keystore = @KeyStore(location = "classpath:/keystore.p12", password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}, type = "PKCS12"), alias = "test"), algorithm = "SHA512withRSA")
        private EncodingVerifier verifier;
        @Signer(privateKey = @PrivateKey(keystore = @KeyStore(location = "classpath:/keystore.p12", password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}, type = "PKCS12"), alias = "test", password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}), algorithm = "SHA512withRSA")
        private EncodingSigner signer;

        public EncodingVerifier verifier() {
            return verifier;
        }

        public EncodingSigner signer() {
            return signer;
        }
    }
}
