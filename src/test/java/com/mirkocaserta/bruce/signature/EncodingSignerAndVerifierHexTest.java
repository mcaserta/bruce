package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;

import static com.mirkocaserta.bruce.Bruce.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EncodingSignerAndVerifierHexTest extends EncodingSignerAndVerifierCommonTest {

    @Override
    protected EncodingSigner getSigner() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        return Bruce.signer(privateKey(keystore, "test", "password"), Bruce.Encoding.HEX);
    }

    @Override
    protected EncodingVerifier getVerifier() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        return Bruce.verifier(publicKey(keystore, "test"), Bruce.Encoding.HEX);
    }

    @Test
    void signerAndVerifiersWithWrongParamsShouldFail() {
        final KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        assertThrows(BruceException.class, () -> Bruce.signer(privateKey(keystore, "sgiao belo", "password"), Bruce.Encoding.HEX));
        assertThrows(BruceException.class, () -> Bruce.signer(privateKey(keystore, "test", "sgiao belo"), Bruce.Encoding.HEX));
        assertThrows(BruceException.class, () -> Bruce.verifier(publicKey(keystore, "sgiao belo"), Bruce.Encoding.HEX));
    }

}
