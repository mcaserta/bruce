package com.mirkocaserta.bruce.key;

import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static com.mirkocaserta.bruce.Bruce.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DsaKeyPairWithSecureRandomTest {

    private static final byte[] MESSAGE = "Hello".getBytes(UTF_8);

    @Test
    void generateAndUse() throws NoSuchAlgorithmException {
        var random = SecureRandom.getInstanceStrong();
        var keyPair = keyPair("DSA", 2048, random);
        var signer = signer(keyPair.getPrivate(), "SHA256withDSA");
        var verifier = verifier(keyPair.getPublic(), "SHA256withDSA");
        var signature = signer.sign(MESSAGE);
        assertTrue(verifier.verify(MESSAGE, signature));
    }

}
