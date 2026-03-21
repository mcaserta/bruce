package com.mirkocaserta.bruce.impl.signature;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

import static com.mirkocaserta.bruce.Keystores.keyPair;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureOperationsTest {

    @Test
    void encodingSignerAndVerifierRejectNullEncodingAndCharset() {
        KeyPair kp = keyPair("RSA", 2048);
        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();

        assertThrows(BruceException.class,
                () -> SignatureOperations.createEncodingSigner(privateKey, "SHA256withRSA", "", StandardCharsets.UTF_8, null));
        assertThrows(BruceException.class,
                () -> SignatureOperations.createEncodingSigner(privateKey, "SHA256withRSA", "", null, Bruce.Encoding.BASE64));

        assertThrows(BruceException.class,
                () -> SignatureOperations.createEncodingVerifier(publicKey, "SHA256withRSA", "", StandardCharsets.UTF_8, null));
        assertThrows(BruceException.class,
                () -> SignatureOperations.createEncodingVerifier(publicKey, "SHA256withRSA", "", null, Bruce.Encoding.BASE64));
    }

    @Test
    void keyLookupErrorsAreReported() {
        KeyPair kp = keyPair("RSA", 2048);

        var signerByKey = SignatureOperations.createSignerByKey(Map.of("known", kp.getPrivate()), "SHA256withRSA");
        assertThrows(BruceException.class, () -> signerByKey.sign("missing", "abc".getBytes(StandardCharsets.UTF_8)));

        var verifierByKey = SignatureOperations.createVerifierByKey(Map.of("known", kp.getPublic()), "SHA256withRSA");
        assertThrows(BruceException.class, () -> verifierByKey.verify("missing", "abc".getBytes(StandardCharsets.UTF_8), new byte[]{1, 2}));

        var encodingSignerByKey = SignatureOperations.createEncodingSignerByKey(
                Map.of("known", kp.getPrivate()), "SHA256withRSA", Bruce.Encoding.BASE64);
        assertThrows(BruceException.class, () -> encodingSignerByKey.sign("missing", "abc"));

        var encodingVerifierByKey = SignatureOperations.createEncodingVerifierByKey(
                Map.of("known", kp.getPublic()), "SHA256withRSA", Bruce.Encoding.BASE64);
        assertThrows(BruceException.class, () -> encodingVerifierByKey.verify("missing", "abc", "Zm9v"));
    }

    @Test
    void encodingOverloadsProduceUsableSignerAndVerifier() {
        KeyPair kp = keyPair("RSA", 2048);

        var signer = SignatureOperations.createEncodingSigner(kp.getPrivate(), "SHA256withRSA", Bruce.Encoding.BASE64);
        var verifier = SignatureOperations.createEncodingVerifier(kp.getPublic(), "SHA256withRSA", Bruce.Encoding.BASE64);
        String signature = signer.sign("hello-signature-overloads");
        assertTrue(verifier.verify("hello-signature-overloads", signature));

        var signerWithCharset = SignatureOperations.createEncodingSigner(
                kp.getPrivate(), "SHA256withRSA", StandardCharsets.UTF_8, Bruce.Encoding.BASE64);
        var verifierWithCharset = SignatureOperations.createEncodingVerifierByKey(
                Map.of("k1", kp.getPublic()), "SHA256withRSA", StandardCharsets.UTF_8, Bruce.Encoding.BASE64);

        String sig2 = signerWithCharset.sign("hello-charset");
        assertTrue(verifierWithCharset.verify("k1", "hello-charset", sig2));
    }
}

