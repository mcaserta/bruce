package com.mirkocaserta.bruce.key;

import com.mirkocaserta.bruce.BruceException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static com.mirkocaserta.bruce.Bruce.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaKeyPairWithCustomProviderTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final byte[] MESSAGE = "Hello".getBytes(UTF_8);

    @Test
    void generateAndUse() {
        var keyPair = keyPair("RSA", "BC", 4096);
        var signer = signer(keyPair.getPrivate(), "RIPEMD160withRSA/ISO9796-2");
        var verifier = verifier(keyPair.getPublic(), "RIPEMD160withRSA/ISO9796-2");
        var signature = signer.sign(MESSAGE);
        assertTrue(verifier.verify(MESSAGE, signature));
    }

    @Test
    void noSuchProvider() {
        assertThrows(BruceException.class, () -> keyPair("RSA", "sgiao belo", 2048));
    }

}
