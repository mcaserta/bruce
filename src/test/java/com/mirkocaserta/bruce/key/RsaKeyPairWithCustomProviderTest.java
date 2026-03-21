package com.mirkocaserta.bruce.key;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Bytes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Bruce.verifierBuilder;
import static com.mirkocaserta.bruce.Keystores.keyPair;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaKeyPairWithCustomProviderTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Bytes MESSAGE = Bytes.from("Hello");

    @Test
    void generateAndUse() {
        var keyPair = keyPair("RSA", "BC", 4096);
        var signer = signerBuilder().key(keyPair.getPrivate()).algorithm("RIPEMD160withRSA/ISO9796-2").build();
        var verifier = verifierBuilder().key(keyPair.getPublic()).algorithm("RIPEMD160withRSA/ISO9796-2").build();
        var signature = signer.sign(MESSAGE);
        assertTrue(verifier.verify(MESSAGE, signature));
    }

    @Test
    void noSuchProvider() {
        assertThrows(BruceException.class, () -> keyPair("RSA", "sgiao belo", 2048));
    }

}
