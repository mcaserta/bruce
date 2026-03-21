package com.mirkocaserta.bruce.key;

import com.mirkocaserta.bruce.Bytes;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Bruce.verifierBuilder;
import static com.mirkocaserta.bruce.Keystores.keyPair;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaKeyPairWithSecureRandomTest {

    private static final Bytes MESSAGE = Bytes.from("Hello");

    @Test
    void generateAndUse() throws NoSuchAlgorithmException {
        var random = SecureRandom.getInstanceStrong();
        random.setSeed(new byte[]{0, 1, 2, 3, 4, 5});
        var keyPair = keyPair("RSA", 4096, random);
        var signer = signerBuilder().key(keyPair.getPrivate()).algorithm("SHA512withRSA").build();
        var verifier = verifierBuilder().key(keyPair.getPublic()).algorithm("SHA512withRSA").build();
        var signature = signer.sign(MESSAGE);
        assertTrue(verifier.verify(MESSAGE, signature));
    }

}
