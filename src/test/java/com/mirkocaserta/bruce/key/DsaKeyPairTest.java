package com.mirkocaserta.bruce.key;

import org.junit.jupiter.api.Test;

import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Bruce.verifierBuilder;
import static com.mirkocaserta.bruce.Keystores.keyPair;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DsaKeyPairTest {

    private static final byte[] MESSAGE = "Hello".getBytes(UTF_8);

    @Test
    void generateAndUse() {
        var keyPair = keyPair("DSA", 2048);
        var signer = signerBuilder().key(keyPair.getPrivate()).algorithm("SHA256withDSA").buildRaw();
        var verifier = verifierBuilder().key(keyPair.getPublic()).algorithm("SHA256withDSA").buildRaw();
        var signature = signer.sign(MESSAGE);
        assertTrue(verifier.verify(MESSAGE, signature));
    }

}
