package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Map;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.Keystores.*;
import static org.junit.jupiter.api.Assertions.*;

class UnifiedApiRoundTripTest {

    @Test
    void digesterProducesConsistentBytes() {
        var digester = Bruce.digestBuilder().algorithm("SHA-256").build();
        Bytes hash1 = digester.digest(Bytes.from("payload"));
        Bytes hash2 = digester.digest(Bytes.from("payload"));
        assertEquals(hash1, hash2);
        assertEquals(32, hash1.length());
        assertFalse(hash1.encode(BASE64).isBlank());
        assertFalse(hash1.encode(Bruce.Encoding.HEX).isBlank());
    }

    @Test
    void macProducesConsistentBytes() {
        var keyStore = Keystores.keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        var secretKey = Keystores.secretKey(keyStore, "hmac", "password".toCharArray());
        var mac = Bruce.macBuilder().key(secretKey).algorithm("HmacSHA1").build();
        Bytes result1 = mac.get(Bytes.from("payload"));
        Bytes result2 = mac.get(Bytes.from("payload"));
        assertEquals(result1, result2);
    }

    @Test
    void signatureSupportsBytesRoundTrip() {
        var keyPair = Keystores.keyPair("RSA", 2048);
        var signer   = Bruce.signerBuilder().key(keyPair.getPrivate()).algorithm("SHA256withRSA").build();
        var verifier = Bruce.verifierBuilder().key(keyPair.getPublic()).algorithm("SHA256withRSA").build();

        Bytes message   = Bytes.from("mixed-signature");
        Bytes signature = signer.sign(message);
        assertTrue(verifier.verify(message, signature));
        assertTrue(verifier.verify(message, Bytes.from(signature.encode(BASE64), BASE64)));
    }

    @Test
    void symmetricCipherSupportsCompleteRoundTrip() {
        byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(ivBytes);
        Bytes iv  = Bytes.from(ivBytes);
        Bytes key = Bytes.from(symmetricKey("AES", BASE64), BASE64);

        var encryptor = Bruce.cipherBuilder().key(key).keyAlgorithm("AES").algorithm("AES/CBC/PKCS5Padding").buildSymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder().key(key).keyAlgorithm("AES").algorithm("AES/CBC/PKCS5Padding").buildSymmetricDecryptor();

        Bytes plaintext  = Bytes.from("clear text");
        Bytes ciphertext = encryptor.encrypt(iv, plaintext);
        assertEquals("clear text", decryptor.decrypt(iv, ciphertext).asString());
    }

    @Test
    void asymmetricCipherAndByKeyRoundTrip() {
        var keyPair = Keystores.keyPair("RSA", 2048);

        var encryptor = Bruce.cipherBuilder().key(keyPair.getPublic()).algorithm("RSA").buildAsymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder().key(keyPair.getPrivate()).algorithm("RSA").buildAsymmetricDecryptor();

        Bytes ciphertext = encryptor.encrypt(Bytes.from("hello asymmetric"));
        assertEquals("hello asymmetric", decryptor.decrypt(ciphertext).asString());

        var encryptorByKey = Bruce.cipherBuilder().keys(Map.of("pub", keyPair.getPublic())).algorithm("RSA").buildAsymmetricEncryptorByKey();
        var decryptorByKey = Bruce.cipherBuilder().keys(Map.of("priv", keyPair.getPrivate())).algorithm("RSA").buildAsymmetricDecryptorByKey();
        Bytes cipher2 = encryptorByKey.encrypt("pub", Bytes.from("hello by key"));
        assertEquals("hello by key", decryptorByKey.decrypt("priv", cipher2).asString());
    }
}

