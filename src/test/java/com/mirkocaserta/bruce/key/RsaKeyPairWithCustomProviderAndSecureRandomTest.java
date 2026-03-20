package com.mirkocaserta.bruce.key;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Bruce.verifierBuilder;
import static com.mirkocaserta.bruce.Keystores.keyPair;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaKeyPairWithCustomProviderAndSecureRandomTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final byte[] MESSAGE = "Hello".getBytes(UTF_8);

    @Test
    void generateAndUse() throws NoSuchAlgorithmException {
        var random = SecureRandom.getInstanceStrong();
        var keyPair = keyPair("RSA", "BC", 4096, random);
        var signer = signerBuilder().key(keyPair.getPrivate()).algorithm("WHIRLPOOLwithRSA/X9.31").buildRaw();
        var verifier = verifierBuilder().key(keyPair.getPublic()).algorithm("WHIRLPOOLwithRSA/X9.31").buildRaw();
        var signature = signer.sign(MESSAGE);
        assertTrue(verifier.verify(MESSAGE, signature));
    }

}
