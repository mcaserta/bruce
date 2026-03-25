package com.mirkocaserta.bruce.key;

import com.mirkocaserta.bruce.Bytes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import static com.mirkocaserta.bruce.Bruce.Provider.BOUNCY_CASTLE;
import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Bruce.verifierBuilder;
import static com.mirkocaserta.bruce.Keystores.keyPair;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaKeyPairWithCustomProviderAndSecureRandomTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Bytes MESSAGE = Bytes.from("Hello");

    @Test
    void generateAndUse() throws NoSuchAlgorithmException {
        var random = SecureRandom.getInstanceStrong();
        var keyPair = keyPair("RSA", BOUNCY_CASTLE, 4096, random);
        var signer = signerBuilder().key(keyPair.getPrivate()).algorithm("WHIRLPOOLwithRSA/X9.31").build();
        var verifier = verifierBuilder().key(keyPair.getPublic()).algorithm("WHIRLPOOLwithRSA/X9.31").build();
        var signature = signer.sign(MESSAGE);
        assertTrue(verifier.verify(MESSAGE, signature));
    }

}
