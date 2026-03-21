package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.Keystores.*;
import static org.junit.jupiter.api.Assertions.*;

class BuilderTest {

    @Test
    void signerAndVerifierBuildersSupportBytesApi() {
        var keyPair = keyPair("RSA", 2048);

        var signer = Bruce.signerBuilder()
                .key(keyPair.getPrivate())
                .algorithm("SHA256withRSA")
                .build();
        var verifier = Bruce.verifierBuilder()
                .key(keyPair.getPublic())
                .algorithm("SHA256withRSA")
                .build();

        Bytes message   = Bytes.from("hello");
        Bytes signature = signer.sign(message);

        assertNotNull(signature);
        assertFalse(signature.isEmpty());
        assertTrue(verifier.verify(message, signature));

        // Encode and re-wrap to simulate storage/transport
        Bytes restoredSig = Bytes.from(signature.encode(BASE64), BASE64);
        assertTrue(verifier.verify(message, restoredSig));
    }

    @Test
    void digestAndMacBuildersReturnBytes() {
        var digester = Bruce.digestBuilder().algorithm("SHA-256").build();
        Bytes hash = digester.digest(Bytes.from("hello"));
        assertNotNull(hash);
        assertEquals(32, hash.length());
        assertFalse(hash.encode(BASE64).isBlank());

        KeyStore keyStore = keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        var hmacKey = secretKey(keyStore, "hmac", "password".toCharArray());
        var mac = Bruce.macBuilder().key(hmacKey).algorithm("HmacSHA1").build();
        Bytes macResult = mac.get(Bytes.from("payload"));
        assertNotNull(macResult);
        assertFalse(macResult.isEmpty());
    }

    @Test
    void symmetricCipherBuilderRoundTrip() {
        byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(ivBytes);
        Bytes iv  = Bytes.from(ivBytes);
        Bytes key = Bytes.from(symmetricKey("AES", BASE64), BASE64);

        var encryptor = Bruce.cipherBuilder()
                .key(key)
                .keyAlgorithm("AES")
                .algorithm("AES/CBC/PKCS5Padding")
                .buildSymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder()
                .key(key)
                .keyAlgorithm("AES")
                .algorithm("AES/CBC/PKCS5Padding")
                .buildSymmetricDecryptor();

        Bytes plaintext   = Bytes.from("Hello symmetric world");
        Bytes ciphertext  = encryptor.encrypt(iv, plaintext);
        Bytes decrypted   = decryptor.decrypt(iv, ciphertext);

        assertEquals("Hello symmetric world", decrypted.asString());
    }

    @Test
    void asymmetricCipherBuilderRoundTrip() {
        var keyPair = keyPair("RSA", 2048);

        var encryptor = Bruce.cipherBuilder()
                .key(keyPair.getPublic())
                .algorithm("RSA")
                .buildAsymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder()
                .key(keyPair.getPrivate())
                .algorithm("RSA")
                .buildAsymmetricDecryptor();

        Bytes plaintext  = Bytes.from("Hello asymmetric world");
        Bytes ciphertext = encryptor.encrypt(plaintext);
        Bytes decrypted  = decryptor.decrypt(ciphertext);

        assertEquals("Hello asymmetric world", decrypted.asString());
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
        var keyPair = keyPair("RSA", 2048);
        var signer = Bruce.signerBuilder()
                .keys(Map.of("main", keyPair.getPrivate()))
                .algorithm("SHA256withRSA")
                .buildByKey();
        var verifier = Bruce.verifierBuilder()
                .keys(Map.of("main", keyPair.getPublic()))
                .algorithm("SHA256withRSA")
                .buildByKey();

        Bytes message   = Bytes.from("hello-by-key");
        Bytes signature = signer.sign("main", message);
        assertTrue(verifier.verify("main", message, signature));
    }

    @Test
    void builderValidationCoversBranchCases() {
        var keyPair = keyPair("RSA", 2048);
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

    @Test
    void symmetricByKeyBuilderRoundTripAndAlgorithmsShortcut() {
        byte[] rawKey = symmetricKey("AES");
        byte[] rawIv = new byte[16];
        new SecureRandom().nextBytes(rawIv);

        Bytes key = Bytes.from(rawKey);
        Bytes iv = Bytes.from(rawIv);
        Bytes plaintext = Bytes.from("hello-symmetric-by-key");

        var encryptorByKey = Bruce.cipherBuilder()
                .algorithms("AES", "AES/CBC/PKCS5Padding")
                .buildSymmetricEncryptorByKey();
        var decryptorByKey = Bruce.cipherBuilder()
                .algorithms("AES", "AES/CBC/PKCS5Padding")
                .buildSymmetricDecryptorByKey();

        Bytes ciphertext = encryptorByKey.encrypt(key, iv, plaintext);
        Bytes decrypted = decryptorByKey.decrypt(key, iv, ciphertext);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void signerByKeyIsUnaffectedBySubsequentMapMutation() {
        var keyPair = keyPair("RSA", 2048);
        var mutableMap = new java.util.HashMap<String, java.security.PrivateKey>();
        mutableMap.put("alice", keyPair.getPrivate());

        var signer = Bruce.signerBuilder()
                .keys(mutableMap)
                .algorithm("SHA256withRSA")
                .buildByKey();

        var verifier = Bruce.verifierBuilder().key(keyPair.getPublic()).algorithm("SHA256withRSA").build();

        Bytes msg = Bytes.from("hello");
        Bytes sig = signer.sign("alice", msg);
        assertTrue(verifier.verify(msg, sig));

        // Mutate original map — should not affect already-built signer
        mutableMap.clear();
        // Alice key should still resolve from the defensive copy
        assertDoesNotThrow(() -> signer.sign("alice", msg));
    }
}
