package com.mirkocaserta.bruce.key;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Bytes;
import org.junit.jupiter.api.Test;

import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Bruce.verifierBuilder;
import static com.mirkocaserta.bruce.Keystores.keyPair;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaKeyPairTest {

    private static final Bytes MESSAGE = Bytes.from("Hello");

    @Test
    void generateAndUse() {
        var keyPair = keyPair("RSA", 4096);
        var signer = signerBuilder().key(keyPair.getPrivate()).algorithm("SHA512withRSA").build();
        var verifier = verifierBuilder().key(keyPair.getPublic()).algorithm("SHA512withRSA").build();
        var signature = signer.sign(MESSAGE);
        assertTrue(verifier.verify(MESSAGE, signature));
    }

    @Test
    void noSuchAlgorithm() {
        assertThrows(BruceException.class, () -> keyPair("XXX", 2048));
    }

    @Test
    void invalidKeySize() {
        assertThrows(BruceException.class, () -> keyPair("RSA", 23));
    }

}
