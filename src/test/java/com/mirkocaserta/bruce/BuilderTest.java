package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.Mode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.Map;

import static com.mirkocaserta.bruce.Bruce.Encoding;
import static com.mirkocaserta.bruce.Bruce.cipherBuilder;
import static com.mirkocaserta.bruce.Bruce.macBuilder;
import static com.mirkocaserta.bruce.Bruce.signerBuilder;
import static com.mirkocaserta.bruce.Bruce.verifierBuilder;
import static com.mirkocaserta.bruce.Keystores.keyPair;
import static com.mirkocaserta.bruce.Keystores.keystore;
import static com.mirkocaserta.bruce.Keystores.secretKey;
import static com.mirkocaserta.bruce.Keystores.symmetricKey;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the builder pattern implementations for reducing parameter overload.
 */
class BuilderTest {

    @Test
    void testSignerBuilder() {
        // Generate a key pair for testing
        KeyPair keyPair = keyPair("RSA", 2048);
        PrivateKey privateKey = keyPair.getPrivate();
        
        // Test the builder pattern (use default provider instead of SunJSSE)
        var signer = signerBuilder()
                .key(privateKey)
                .algorithm("SHA256withRSA")
                .charset(StandardCharsets.UTF_8)
                .encoding(Encoding.BASE64)
                .build();
        
        assertNotNull(signer);
        
        // Test signing functionality
        String signature = signer.sign("Hello World");
        assertNotNull(signature);
        assertFalse(signature.isEmpty());
    }

    @Test
    void testCipherBuilderSymmetric() {
        String testKey = symmetricKey("AES", Encoding.BASE64);
        
        // Test symmetric cipher builder creation (don't test actual encryption due to complexity)
        var cipher = cipherBuilder()
                .key(testKey)
                .keyAlgorithm("AES")
                .algorithm("AES")
                .mode(Mode.ENCRYPT)
                .charset(StandardCharsets.UTF_8)
                .encoding(Encoding.BASE64)
                .buildSymmetric();
        
        assertNotNull(cipher);
        // Builder successfully created a cipher - that's what we're testing
    }

    @Test
    void testCipherBuilderAsymmetric() {
        KeyPair keyPair = keyPair("RSA", 2048);
        
        // Test asymmetric cipher builder
        var cipher = cipherBuilder()
                .key(keyPair.getPublic())
                .algorithm("RSA")
                .mode(Mode.ENCRYPT)
                .charset(StandardCharsets.UTF_8)
                .encoding(Encoding.BASE64)
                .buildAsymmetric();
        
        assertNotNull(cipher);
        
        // Test encryption functionality
        String encrypted = cipher.encrypt("Hello");
        assertNotNull(encrypted);
        assertFalse(encrypted.isEmpty());
    }

    @Test
    void testBuilderValidation() {
        // Test that builders validate required parameters
        assertThrows(BruceException.class, () -> {
            signerBuilder().build(); // Missing required parameters
        });
        
        assertThrows(BruceException.class, () -> {
            cipherBuilder().buildSymmetric(); // Missing required parameters
        });
        
        assertThrows(BruceException.class, () -> {
            cipherBuilder().buildAsymmetric(); // Missing required parameters
        });
    }

    @Test
    void testBuilderProviderAndConvenienceMethods() {
        String key = symmetricKey("AES", Encoding.BASE64);

        var cipher = cipherBuilder()
                .key(key)
                .algorithms("AES", "AES")
                .provider(null)
                .mode(Mode.ENCRYPT)
                .charset(StandardCharsets.UTF_8)
                .encoding(Encoding.BASE64)
                .buildSymmetric();

        assertNotNull(cipher);

        var digester = Bruce.digestBuilder()
                .algorithm("SHA1")
                .provider(null)
                .charset(StandardCharsets.UTF_8)
                .encoding(Encoding.HEX)
                .build();
        assertNotNull(digester.digest("builder"));

        KeyPair kp = keyPair("RSA", 2048);
        assertNotNull(Bruce.signerBuilder().key(kp.getPrivate()).algorithm("SHA256withRSA").provider(null).buildRaw());
        assertNotNull(Bruce.verifierBuilder().key(kp.getPublic()).algorithm("SHA256withRSA").provider(null).buildRaw());
    }

    @Test
    void testCipherBuilderValidationBranches() {
        assertThrows(BruceException.class, () -> cipherBuilder()
                .keyAlgorithm("AES")
                .algorithm("AES")
                .mode(Mode.ENCRYPT)
                .buildSymmetricRaw());

        assertThrows(BruceException.class, () -> cipherBuilder()
                .algorithm("AES")
                .mode(Mode.ENCRYPT)
                .buildSymmetricRawByKey());

        assertThrows(BruceException.class, () -> cipherBuilder()
                .keyAlgorithm("AES")
                .mode(Mode.ENCRYPT)
                .buildSymmetricRawByKey());

        assertThrows(BruceException.class, () -> cipherBuilder()
                .keyAlgorithm("AES")
                .algorithm("AES")
                .buildSymmetricRawByKey());

        assertThrows(BruceException.class, () -> cipherBuilder()
                .keys(Collections.emptyMap())
                .algorithm("RSA")
                .buildAsymmetricByKey());

        KeyPair keyPair = keyPair("RSA", 2048);
        Map<String, java.security.Key> keys = Map.of("id", keyPair.getPublic());
        assertThrows(BruceException.class, () -> cipherBuilder().keys(keys).buildAsymmetricByKey());

        assertThrows(BruceException.class, () -> cipherBuilder()
                .key("abc")
                .algorithm("AES")
                .mode(Mode.ENCRYPT)
                .buildSymmetric());

        assertThrows(BruceException.class, () -> cipherBuilder()
                .key("abc")
                .keyAlgorithm("AES")
                .mode(Mode.ENCRYPT)
                .buildSymmetric());

        assertThrows(BruceException.class, () -> cipherBuilder()
                .key("abc")
                .keyAlgorithm("AES")
                .algorithm("AES")
                .buildSymmetric());

        assertThrows(BruceException.class, () -> cipherBuilder()
                .key(keyPair.getPublic())
                .mode(Mode.ENCRYPT)
                .buildAsymmetric());

        assertThrows(BruceException.class, () -> cipherBuilder()
                .key(keyPair.getPublic())
                .algorithm("RSA")
                .buildAsymmetric());

        assertNotNull(cipherBuilder().keys(keys).algorithm("RSA").buildAsymmetricRawByKey());

        assertThrows(BruceException.class, () -> cipherBuilder().keys(keys).buildAsymmetricRawByKey());
    }

    @Test
    void testSignerVerifierMacDigestValidationBranches() {
        KeyPair keyPair = keyPair("RSA", 2048);

        assertThrows(BruceException.class, () -> signerBuilder().key(keyPair.getPrivate()).buildRaw());
        assertThrows(BruceException.class, () -> signerBuilder().keys(Collections.emptyMap()).algorithm("SHA256withRSA").buildRawByKey());
        assertThrows(BruceException.class, () -> signerBuilder().keys(Map.of("kid", keyPair.getPrivate())).buildRawByKey());
        assertNotNull(signerBuilder().keys(Map.of("kid", keyPair.getPrivate())).algorithm("SHA256withRSA").provider(null).buildRawByKey());

        assertThrows(BruceException.class, () -> verifierBuilder().key(keyPair.getPublic()).buildRaw());
        assertThrows(BruceException.class, () -> verifierBuilder().keys(Collections.emptyMap()).algorithm("SHA256withRSA").buildRawByKey());
        assertThrows(BruceException.class, () -> verifierBuilder().keys(Map.of("kid", keyPair.getPublic())).buildRawByKey());
        assertNotNull(verifierBuilder().keys(Map.of("kid", keyPair.getPublic())).algorithm("SHA256withRSA").provider(null).buildRawByKey());

        var ks = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        var hmacKey = secretKey(ks, "hmac", "password".toCharArray());
        assertThrows(BruceException.class, () -> macBuilder().algorithm("HmacSHA1").buildRaw());
        assertThrows(BruceException.class, () -> macBuilder().key(hmacKey).buildRaw());
        assertNotNull(macBuilder().key(hmacKey).algorithm("HmacSHA1").provider(null).buildRaw());

        assertThrows(BruceException.class, () -> Bruce.digestBuilder().buildRaw());
    }
}
