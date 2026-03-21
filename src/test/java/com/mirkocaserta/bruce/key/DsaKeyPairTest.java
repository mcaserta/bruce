package com.mirkocaserta.bruce.key;

import com.mirkocaserta.bruce.Bytes;
import org.junit.jupiter.api.Test;

import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Bruce.verifierBuilder;
import static com.mirkocaserta.bruce.Keystores.keyPair;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DsaKeyPairTest {

    private static final Bytes MESSAGE = Bytes.from("Hello");

    @Test
    void generateAndUse() {
        var keyPair = keyPair("DSA", 2048);
        var signer = signerBuilder().key(keyPair.getPrivate()).algorithm("SHA256withDSA").build();
        var verifier = verifierBuilder().key(keyPair.getPublic()).algorithm("SHA256withDSA").build();
        var signature = signer.sign(MESSAGE);
        assertTrue(verifier.verify(MESSAGE, signature));
    }

}
