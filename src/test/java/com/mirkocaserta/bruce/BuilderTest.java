package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricDecryptor;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricEncryptor;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricDecryptor;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricEncryptor;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

import static com.mirkocaserta.bruce.Keystores.keyPair;
import static com.mirkocaserta.bruce.Keystores.keystore;
import static com.mirkocaserta.bruce.Keystores.secretKey;
import static com.mirkocaserta.bruce.Keystores.symmetricKey;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BuilderTest {

    @Test
    void signerAndVerifierBuildersSupportRawAndEncodedRepresentations() {
        KeyPair keyPair = keyPair("RSA", 2048);

        var signer = Bruce.signerBuilder()
                .key(keyPair.getPrivate())
                .algorithm("SHA256withRSA")
                .build();
        var verifier = Bruce.verifierBuilder()
                .key(keyPair.getPublic())
                .algorithm("SHA256withRSA")
                .build();

        byte[] rawSignature = signer.sign("hello".getBytes(StandardCharsets.UTF_8));
        String base64Signature = signer.signToString("hello");

        assertTrue(verifier.verify("hello", rawSignature));
        assertTrue(verifier.verify("hello", base64Signature));
    }

    @Test
    void digestAndMacBuildersUseDefaultBase64Encoding() {
        var digester = Bruce.digestBuilder().algorithm("SHA-256").build();
        assertFalse(digester.digestToString("hello").isBlank());
        assertArrayEquals(digester.digest("hello"), Base64.getDecoder().decode(digester.digestToString("hello")));

        KeyStore keyStore = keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        var hmacKey = secretKey(keyStore, "hmac", "password".toCharArray());
        var mac = Bruce.macBuilder().key(hmacKey).algorithm("HmacSHA1").build();
        assertNotNull(mac.getToString("payload"));
    }

    @Test
    void symmetricCipherBuilderRoundTrip() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        String key = symmetricKey("AES", Bruce.Encoding.BASE64);

        SymmetricEncryptor encryptor = Bruce.cipherBuilder()
                .key(key)
                .keyAlgorithm("AES")
                .algorithm("AES/CBC/PKCS5Padding")
                .buildSymmetricEncryptor();
        SymmetricDecryptor decryptor = Bruce.cipherBuilder()
                .key(key)
                .keyAlgorithm("AES")
                .algorithm("AES/CBC/PKCS5Padding")
                .buildSymmetricDecryptor();

        String cipherText = encryptor.encryptToString(iv, "Hello symmetric world");
        String plainText = decryptor.decryptToString(iv, cipherText);

        assertEquals("Hello symmetric world", plainText);
    }

    @Test
    void asymmetricCipherBuilderRoundTrip() {
        KeyPair keyPair = keyPair("RSA", 2048);

        AsymmetricEncryptor encryptor = Bruce.cipherBuilder()
                .key(keyPair.getPublic())
                .algorithm("RSA")
                .buildAsymmetricEncryptor();
        AsymmetricDecryptor decryptor = Bruce.cipherBuilder()
                .key(keyPair.getPrivate())
                .algorithm("RSA")
                .buildAsymmetricDecryptor();

        String cipherText = encryptor.encryptToString("Hello asymmetric world");
        String plainText = decryptor.decryptToString(cipherText);

        assertEquals("Hello asymmetric world", plainText);
    }

    @Test
    void builderValidationRejectsMissingRequiredParameters() {
        assertThrows(BruceException.class, () -> Bruce.digestBuilder().build());
        assertThrows(BruceException.class, () -> Bruce.macBuilder().build());
        assertThrows(BruceException.class, () -> Bruce.signerBuilder().build());
        assertThrows(BruceException.class, () -> Bruce.verifierBuilder().build());
        assertThrows(BruceException.class, () -> Bruce.cipherBuilder().buildSymmetricEncryptor());
        assertThrows(BruceException.class, () -> Bruce.cipherBuilder().buildAsymmetricEncryptor());
        assertThrows(BruceException.class, () -> Bruce.cipherBuilder().buildSymmetricEncryptorByKey());
        assertThrows(BruceException.class, () -> Bruce.cipherBuilder().buildAsymmetricEncryptorByKey());
    }

    @Test
    void builderByKeyVariantsWork() {
        KeyPair keyPair = keyPair("RSA", 2048);
        var signer = Bruce.signerBuilder()
                .keys(Map.of("main", keyPair.getPrivate()))
                .algorithm("SHA256withRSA")
                .buildByKey();
        var verifier = Bruce.verifierBuilder()
                .keys(Map.of("main", keyPair.getPublic()))
                .algorithm("SHA256withRSA")
                .buildByKey();

        String signature = signer.signToString("main", "hello-by-key");
        assertTrue(verifier.verify("main", "hello-by-key", signature));
    }

    @Test
    void builderValidationCoversBranchCases() {
        KeyPair keyPair = keyPair("RSA", 2048);
        KeyStore keyStore = keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        var hmacKey = secretKey(keyStore, "hmac", "password".toCharArray());

        assertThrows(BruceException.class, () -> Bruce.signerBuilder().key(keyPair.getPrivate()).build());
        assertThrows(BruceException.class, () -> Bruce.signerBuilder().keys(Collections.emptyMap()).algorithm("SHA256withRSA").buildByKey());
        assertThrows(BruceException.class, () -> Bruce.verifierBuilder().key(keyPair.getPublic()).build());
        assertThrows(BruceException.class, () -> Bruce.verifierBuilder().keys(Collections.emptyMap()).algorithm("SHA256withRSA").buildByKey());
        assertThrows(BruceException.class, () -> Bruce.macBuilder().algorithm("HmacSHA1").build());
        assertThrows(BruceException.class, () -> Bruce.macBuilder().key(hmacKey).build());
        assertThrows(BruceException.class, () -> Bruce.cipherBuilder().algorithm("AES/CBC/PKCS5Padding").buildSymmetricEncryptorByKey());
        assertThrows(BruceException.class, () -> Bruce.cipherBuilder().keyAlgorithm("AES").buildSymmetricEncryptorByKey());
        assertThrows(BruceException.class, () -> Bruce.cipherBuilder().keys(Collections.emptyMap()).algorithm("RSA").buildAsymmetricEncryptorByKey());
        assertThrows(BruceException.class, () -> Bruce.cipherBuilder().keys(Map.of("key", keyPair.getPublic())).buildAsymmetricEncryptorByKey());
        assertNotNull(Bruce.macBuilder().key(hmacKey).algorithm("HmacSHA1").provider(null).build());
    }
}
