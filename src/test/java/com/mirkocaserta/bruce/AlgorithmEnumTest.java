package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.SecureRandom;
import java.util.Map;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.Keystores.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the type-safe algorithm enum API introduced in issue #205.
 *
 * <p>These tests verify that each enum-accepting builder overload produces
 * results equivalent to the existing string-based overload, and that
 * all enum constants carry the expected JCA algorithm name.
 */
class AlgorithmEnumTest {

    // ── AlgorithmId contract ─────────────────────────────────────────────────

    @ParameterizedTest
    @EnumSource(DigestAlgorithm.class)
    void digestAlgorithmNamesAreNonBlank(DigestAlgorithm algo) {
        assertNotNull(algo.algorithmName(), "algorithmName() must not be null for " + algo);
        assertFalse(algo.algorithmName().isBlank(), "algorithmName() must not be blank for " + algo);
    }

    @ParameterizedTest
    @EnumSource(MacAlgorithm.class)
    void macAlgorithmNamesAreNonBlank(MacAlgorithm algo) {
        assertNotNull(algo.algorithmName());
        assertFalse(algo.algorithmName().isBlank());
    }

    @ParameterizedTest
    @EnumSource(SignatureAlgorithm.class)
    void signatureAlgorithmNamesAreNonBlank(SignatureAlgorithm algo) {
        assertNotNull(algo.algorithmName());
        assertFalse(algo.algorithmName().isBlank());
    }

    @ParameterizedTest
    @EnumSource(SymmetricAlgorithm.class)
    void symmetricAlgorithmNamesAreNonBlank(SymmetricAlgorithm algo) {
        assertNotNull(algo.algorithmName());
        assertFalse(algo.algorithmName().isBlank());
    }

    @ParameterizedTest
    @EnumSource(SymmetricCipherAlgorithm.class)
    void symmetricCipherAlgorithmNamesAreNonBlank(SymmetricCipherAlgorithm algo) {
        assertNotNull(algo.algorithmName());
        assertFalse(algo.algorithmName().isBlank());
    }

    @ParameterizedTest
    @EnumSource(AsymmetricAlgorithm.class)
    void asymmetricAlgorithmNamesAreNonBlank(AsymmetricAlgorithm algo) {
        assertNotNull(algo.algorithmName());
        assertFalse(algo.algorithmName().isBlank());
    }

    // ── DigestAlgorithm enum constants ───────────────────────────────────────

    @Test
    void digestAlgorithmConstantsHaveExpectedJcaNames() {
        assertEquals("MD5",        DigestAlgorithm.MD5.algorithmName());
        assertEquals("SHA-1",      DigestAlgorithm.SHA_1.algorithmName());
        assertEquals("SHA-224",    DigestAlgorithm.SHA_224.algorithmName());
        assertEquals("SHA-256",    DigestAlgorithm.SHA_256.algorithmName());
        assertEquals("SHA-384",    DigestAlgorithm.SHA_384.algorithmName());
        assertEquals("SHA-512",    DigestAlgorithm.SHA_512.algorithmName());
        assertEquals("SHA-512/224",DigestAlgorithm.SHA_512_224.algorithmName());
        assertEquals("SHA-512/256",DigestAlgorithm.SHA_512_256.algorithmName());
        assertEquals("SHA3-224",   DigestAlgorithm.SHA3_224.algorithmName());
        assertEquals("SHA3-256",   DigestAlgorithm.SHA3_256.algorithmName());
        assertEquals("SHA3-384",   DigestAlgorithm.SHA3_384.algorithmName());
        assertEquals("SHA3-512",   DigestAlgorithm.SHA3_512.algorithmName());
    }

    @Test
    void macAlgorithmConstantsHaveExpectedJcaNames() {
        assertEquals("HmacMD5",        MacAlgorithm.HMAC_MD5.algorithmName());
        assertEquals("HmacSHA1",       MacAlgorithm.HMAC_SHA_1.algorithmName());
        assertEquals("HmacSHA224",     MacAlgorithm.HMAC_SHA_224.algorithmName());
        assertEquals("HmacSHA256",     MacAlgorithm.HMAC_SHA_256.algorithmName());
        assertEquals("HmacSHA384",     MacAlgorithm.HMAC_SHA_384.algorithmName());
        assertEquals("HmacSHA512",     MacAlgorithm.HMAC_SHA_512.algorithmName());
        assertEquals("HmacSHA512/224", MacAlgorithm.HMAC_SHA_512_224.algorithmName());
        assertEquals("HmacSHA512/256", MacAlgorithm.HMAC_SHA_512_256.algorithmName());
        assertEquals("HmacSHA3-224",   MacAlgorithm.HMAC_SHA3_224.algorithmName());
        assertEquals("HmacSHA3-256",   MacAlgorithm.HMAC_SHA3_256.algorithmName());
        assertEquals("HmacSHA3-384",   MacAlgorithm.HMAC_SHA3_384.algorithmName());
        assertEquals("HmacSHA3-512",   MacAlgorithm.HMAC_SHA3_512.algorithmName());
    }

    @Test
    void signatureAlgorithmConstantsHaveExpectedJcaNames() {
        assertEquals("MD5withRSA",       SignatureAlgorithm.MD5_WITH_RSA.algorithmName());
        assertEquals("SHA1withRSA",      SignatureAlgorithm.SHA1_WITH_RSA.algorithmName());
        assertEquals("SHA256withRSA",    SignatureAlgorithm.SHA256_WITH_RSA.algorithmName());
        assertEquals("SHA384withRSA",    SignatureAlgorithm.SHA384_WITH_RSA.algorithmName());
        assertEquals("SHA512withRSA",    SignatureAlgorithm.SHA512_WITH_RSA.algorithmName());
        assertEquals("RSASSA-PSS",       SignatureAlgorithm.RSASSA_PSS.algorithmName());
        assertEquals("SHA1withDSA",      SignatureAlgorithm.SHA1_WITH_DSA.algorithmName());
        assertEquals("SHA256withDSA",    SignatureAlgorithm.SHA256_WITH_DSA.algorithmName());
        assertEquals("SHA1withECDSA",    SignatureAlgorithm.SHA1_WITH_ECDSA.algorithmName());
        assertEquals("SHA256withECDSA",  SignatureAlgorithm.SHA256_WITH_ECDSA.algorithmName());
        assertEquals("SHA384withECDSA",  SignatureAlgorithm.SHA384_WITH_ECDSA.algorithmName());
        assertEquals("SHA512withECDSA",  SignatureAlgorithm.SHA512_WITH_ECDSA.algorithmName());
    }

    @Test
    void symmetricAlgorithmConstantsHaveExpectedJcaNames() {
        assertEquals("AES",      SymmetricAlgorithm.AES.algorithmName());
        assertEquals("DES",      SymmetricAlgorithm.DES.algorithmName());
        assertEquals("DESede",   SymmetricAlgorithm.DESEDE.algorithmName());
        assertEquals("Blowfish", SymmetricAlgorithm.BLOWFISH.algorithmName());
        assertEquals("RC2",      SymmetricAlgorithm.RC2.algorithmName());
        assertEquals("RC4",      SymmetricAlgorithm.RC4.algorithmName());
        assertEquals("ChaCha20", SymmetricAlgorithm.CHACHA20.algorithmName());
    }

    @Test
    void symmetricCipherAlgorithmConstantsHaveExpectedJcaNames() {
        assertEquals("AES/CBC/PKCS5Padding",  SymmetricCipherAlgorithm.AES_CBC_PKCS5.algorithmName());
        assertEquals("AES/CBC/NoPadding",      SymmetricCipherAlgorithm.AES_CBC_NO_PADDING.algorithmName());
        assertEquals("AES/CTR/NoPadding",      SymmetricCipherAlgorithm.AES_CTR_NO_PADDING.algorithmName());
        assertEquals("AES/ECB/PKCS5Padding",  SymmetricCipherAlgorithm.AES_ECB_PKCS5.algorithmName());
        assertEquals("AES/ECB/NoPadding",      SymmetricCipherAlgorithm.AES_ECB_NO_PADDING.algorithmName());
        assertEquals("AES/GCM/NoPadding",      SymmetricCipherAlgorithm.AES_GCM_NO_PADDING.algorithmName());
        assertEquals("DES/CBC/PKCS5Padding",  SymmetricCipherAlgorithm.DES_CBC_PKCS5.algorithmName());
        assertEquals("DES/ECB/PKCS5Padding",  SymmetricCipherAlgorithm.DES_ECB_PKCS5.algorithmName());
        assertEquals("DESede/CBC/PKCS5Padding", SymmetricCipherAlgorithm.DESEDE_CBC_PKCS5.algorithmName());
        assertEquals("DESede/ECB/PKCS5Padding", SymmetricCipherAlgorithm.DESEDE_ECB_PKCS5.algorithmName());
        assertEquals("Blowfish/CBC/PKCS5Padding", SymmetricCipherAlgorithm.BLOWFISH_CBC_PKCS5.algorithmName());
        assertEquals("Blowfish/ECB/PKCS5Padding", SymmetricCipherAlgorithm.BLOWFISH_ECB_PKCS5.algorithmName());
    }

    @Test
    void asymmetricAlgorithmConstantsHaveExpectedJcaNames() {
        assertEquals("RSA",                                        AsymmetricAlgorithm.RSA.algorithmName());
        assertEquals("RSA/ECB/PKCS1Padding",                      AsymmetricAlgorithm.RSA_ECB_PKCS1.algorithmName());
        assertEquals("RSA/ECB/OAEPWithSHA-1AndMGF1Padding",      AsymmetricAlgorithm.RSA_ECB_OAEP_SHA1_MGF1.algorithmName());
        assertEquals("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",    AsymmetricAlgorithm.RSA_ECB_OAEP_SHA256_MGF1.algorithmName());
        assertEquals("RSA/ECB/OAEPWithSHA-384AndMGF1Padding",    AsymmetricAlgorithm.RSA_ECB_OAEP_SHA384_MGF1.algorithmName());
        assertEquals("RSA/ECB/OAEPWithSHA-512AndMGF1Padding",    AsymmetricAlgorithm.RSA_ECB_OAEP_SHA512_MGF1.algorithmName());
        assertEquals("RSA/ECB/NoPadding",                         AsymmetricAlgorithm.RSA_ECB_NO_PADDING.algorithmName());
    }

    // ── DigestBuilder enum overload ──────────────────────────────────────────

    @Test
    void digestBuilderAcceptsEnumAlgorithm() {
        var digester = Bruce.digestBuilder()
                .algorithm(DigestAlgorithm.SHA_256)
                .build();
        Bytes result = digester.digest(Bytes.from("hello"));
        assertEquals(32, result.length(), "SHA-256 should produce 32 bytes");
    }

    @Test
    void digestBuilderEnumProducesSameResultAsString() {
        Bytes fromEnum   = Bruce.digestBuilder().algorithm(DigestAlgorithm.SHA_256).build().digest(Bytes.from("hello"));
        Bytes fromString = Bruce.digestBuilder().algorithm("SHA-256").build().digest(Bytes.from("hello"));
        assertEquals(fromString, fromEnum);
    }

    @Test
    void digestBuilderRejectsNullEnumAlgorithm() {
        assertThrows(BruceException.class, () ->
                Bruce.digestBuilder().algorithm((DigestAlgorithm) null).build());
    }

    // ── MacBuilder enum overload ─────────────────────────────────────────────

    @Test
    void macBuilderAcceptsEnumAlgorithm() {
        var keyStore = keystore("classpath:/keystore.p12", "password".toCharArray(), DEFAULT_KEYSTORE_TYPE);
        var hmacKey  = secretKey(keyStore, "hmac", "password".toCharArray());

        var mac = Bruce.macBuilder()
                .key(hmacKey)
                .algorithm(MacAlgorithm.HMAC_SHA_1)
                .build();
        Bytes result = mac.get(Bytes.from("payload"));
        assertFalse(result.isEmpty());
    }

    @Test
    void macBuilderEnumProducesSameResultAsString() {
        var keyStore = keystore("classpath:/keystore.p12", "password".toCharArray(), DEFAULT_KEYSTORE_TYPE);
        var hmacKey  = secretKey(keyStore, "hmac", "password".toCharArray());
        Bytes msg    = Bytes.from("test-mac-enum");

        Bytes fromEnum   = Bruce.macBuilder().key(hmacKey).algorithm(MacAlgorithm.HMAC_SHA_1).build().get(msg);
        Bytes fromString = Bruce.macBuilder().key(hmacKey).algorithm("HmacSHA1").build().get(msg);
        assertEquals(fromString, fromEnum);
    }

    @Test
    void macBuilderRejectsNullEnumAlgorithm() {
        var keyStore = keystore("classpath:/keystore.p12", "password".toCharArray(), DEFAULT_KEYSTORE_TYPE);
        var hmacKey  = secretKey(keyStore, "hmac", "password".toCharArray());
        assertThrows(BruceException.class, () ->
                Bruce.macBuilder().key(hmacKey).algorithm((MacAlgorithm) null).build());
    }

    // ── SignerBuilder / VerifierBuilder enum overloads ───────────────────────

    @Test
    void signerBuilderAcceptsEnumAlgorithm() {
        var keyPair = keyPair("RSA", 2048);

        var signer = Bruce.signerBuilder()
                .key(keyPair.getPrivate())
                .algorithm(SignatureAlgorithm.SHA256_WITH_RSA)
                .build();
        var verifier = Bruce.verifierBuilder()
                .key(keyPair.getPublic())
                .algorithm(SignatureAlgorithm.SHA256_WITH_RSA)
                .build();

        Bytes msg = Bytes.from("sign-verify-enum");
        Bytes sig = signer.sign(msg);
        assertTrue(verifier.verify(msg, sig));
    }

    @Test
    void signerBuilderEnumProducesSameResultAsString() {
        var keyPair = keyPair("RSA", 2048);

        var signerEnum   = Bruce.signerBuilder().key(keyPair.getPrivate()).algorithm(SignatureAlgorithm.SHA256_WITH_RSA).build();
        var signerString = Bruce.signerBuilder().key(keyPair.getPrivate()).algorithm("SHA256withRSA").build();
        var verifier     = Bruce.verifierBuilder().key(keyPair.getPublic()).algorithm("SHA256withRSA").build();

        Bytes msg      = Bytes.from("enum-string-parity");
        Bytes sigEnum  = signerEnum.sign(msg);
        Bytes sigStr   = signerString.sign(msg);

        // Both signatures should verify correctly (signatures differ per run due to random padding)
        assertTrue(verifier.verify(msg, sigEnum));
        assertTrue(verifier.verify(msg, sigStr));
    }

    @Test
    void signerBuilderRejectsNullEnumAlgorithm() {
        var keyPair = keyPair("RSA", 2048);
        assertThrows(BruceException.class, () ->
                Bruce.signerBuilder().key(keyPair.getPrivate()).algorithm((SignatureAlgorithm) null).build());
    }

    @Test
    void verifierBuilderRejectsNullEnumAlgorithm() {
        var keyPair = keyPair("RSA", 2048);
        assertThrows(BruceException.class, () ->
                Bruce.verifierBuilder().key(keyPair.getPublic()).algorithm((SignatureAlgorithm) null).build());
    }

    @Test
    void signerAndVerifierByKeyWithEnumAlgorithm() {
        var keyPair = keyPair("RSA", 2048);

        var signer = Bruce.signerBuilder()
                .keys(Map.of("main", keyPair.getPrivate()))
                .algorithm(SignatureAlgorithm.SHA256_WITH_RSA)
                .buildByKey();
        var verifier = Bruce.verifierBuilder()
                .keys(Map.of("main", keyPair.getPublic()))
                .algorithm(SignatureAlgorithm.SHA256_WITH_RSA)
                .buildByKey();

        Bytes msg = Bytes.from("by-key-enum");
        Bytes sig = signer.sign("main", msg);
        assertTrue(verifier.verify("main", msg, sig));
    }

    // ── CipherBuilder symmetric enum overloads ───────────────────────────────

    @Test
    void symmetricCipherBuilderAcceptsEnumAlgorithms() {
        byte[] rawIv = new byte[16];
        new SecureRandom().nextBytes(rawIv);
        Bytes iv  = Bytes.from(rawIv);
        Bytes key = Bytes.from(symmetricKey("AES", BASE64), BASE64);

        var encryptor = Bruce.cipherBuilder()
                .key(key)
                .algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_CBC_PKCS5)
                .buildSymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder()
                .key(key)
                .algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_CBC_PKCS5)
                .buildSymmetricDecryptor();

        Bytes plaintext = Bytes.from("hello symmetric enum");
        assertEquals(plaintext, decryptor.decrypt(iv, encryptor.encrypt(iv, plaintext)));
    }

    @Test
    void symmetricCipherBuilderEnumProducesSameResultAsString() {
        byte[] rawIv = new byte[16];
        new SecureRandom().nextBytes(rawIv);
        Bytes iv  = Bytes.from(rawIv);
        Bytes key = Bytes.from(symmetricKey("AES", BASE64), BASE64);
        Bytes msg = Bytes.from("parity-check");

        var encEnum = Bruce.cipherBuilder().key(key)
                .algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_CBC_PKCS5)
                .buildSymmetricEncryptor();
        var encStr = Bruce.cipherBuilder().key(key)
                .algorithms("AES", "AES/CBC/PKCS5Padding")
                .buildSymmetricEncryptor();
        var dec = Bruce.cipherBuilder().key(key)
                .algorithms("AES", "AES/CBC/PKCS5Padding")
                .buildSymmetricDecryptor();

        // Both ciphertexts should decrypt to the same plaintext
        assertEquals(msg, dec.decrypt(iv, encEnum.encrypt(iv, msg)));
        assertEquals(msg, dec.decrypt(iv, encStr.encrypt(iv, msg)));
    }

    @Test
    void symmetricByKeyBuilderAcceptsEnumAlgorithms() {
        byte[] rawIv = new byte[16];
        new SecureRandom().nextBytes(rawIv);
        Bytes iv      = Bytes.from(rawIv);
        Bytes key     = Bytes.from(symmetricKey("AES"));
        Bytes msg     = Bytes.from("by-key-symmetric-enum");

        var encryptor = Bruce.cipherBuilder()
                .algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_CBC_PKCS5)
                .buildSymmetricEncryptorByKey();
        var decryptor = Bruce.cipherBuilder()
                .algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_CBC_PKCS5)
                .buildSymmetricDecryptorByKey();

        assertEquals(msg, decryptor.decrypt(key, iv, encryptor.encrypt(key, iv, msg)));
    }

    @Test
    void cipherBuilderKeyAlgorithmEnumOverload() {
        byte[] rawIv = new byte[16];
        new SecureRandom().nextBytes(rawIv);
        Bytes iv  = Bytes.from(rawIv);
        Bytes key = Bytes.from(symmetricKey("AES", BASE64), BASE64);
        Bytes msg = Bytes.from("key-algo-enum");

        var enc = Bruce.cipherBuilder()
                .key(key)
                .keyAlgorithm(SymmetricAlgorithm.AES)
                .algorithm(SymmetricCipherAlgorithm.AES_CBC_PKCS5)
                .buildSymmetricEncryptor();
        var dec = Bruce.cipherBuilder()
                .key(key)
                .keyAlgorithm(SymmetricAlgorithm.AES)
                .algorithm(SymmetricCipherAlgorithm.AES_CBC_PKCS5)
                .buildSymmetricDecryptor();

        assertEquals(msg, dec.decrypt(iv, enc.encrypt(iv, msg)));
    }

    @Test
    void cipherBuilderRejectsNullSymmetricEnumAlgorithms() {
        assertThrows(BruceException.class, () ->
                Bruce.cipherBuilder().algorithms((SymmetricAlgorithm) null, SymmetricCipherAlgorithm.AES_CBC_PKCS5));
        assertThrows(BruceException.class, () ->
                Bruce.cipherBuilder().algorithms(SymmetricAlgorithm.AES, (SymmetricCipherAlgorithm) null));
        assertThrows(BruceException.class, () ->
                Bruce.cipherBuilder().keyAlgorithm((SymmetricAlgorithm) null));
        assertThrows(BruceException.class, () ->
                Bruce.cipherBuilder().algorithm((SymmetricCipherAlgorithm) null));
        assertThrows(BruceException.class, () ->
                Bruce.cipherBuilder().algorithm((AsymmetricAlgorithm) null));
    }

    // ── CipherBuilder asymmetric enum overloads ──────────────────────────────

    @Test
    void asymmetricCipherBuilderAcceptsEnumAlgorithm() {
        var keyPair = keyPair("RSA", 2048);

        var encryptor = Bruce.cipherBuilder()
                .key(keyPair.getPublic())
                .algorithm(AsymmetricAlgorithm.RSA_ECB_PKCS1)
                .buildAsymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder()
                .key(keyPair.getPrivate())
                .algorithm(AsymmetricAlgorithm.RSA_ECB_PKCS1)
                .buildAsymmetricDecryptor();

        Bytes msg = Bytes.from("hello asymmetric enum");
        assertEquals(msg, decryptor.decrypt(encryptor.encrypt(msg)));
    }

    @Test
    void asymmetricCipherBuilderEnumProducesSameResultAsString() {
        var keyPair = keyPair("RSA", 2048);
        Bytes msg   = Bytes.from("asymmetric-parity");

        var encEnum = Bruce.cipherBuilder().key(keyPair.getPublic())
                .algorithm(AsymmetricAlgorithm.RSA_ECB_PKCS1)
                .buildAsymmetricEncryptor();
        var encStr  = Bruce.cipherBuilder().key(keyPair.getPublic())
                .algorithm("RSA/ECB/PKCS1Padding")
                .buildAsymmetricEncryptor();
        var dec     = Bruce.cipherBuilder().key(keyPair.getPrivate())
                .algorithm("RSA/ECB/PKCS1Padding")
                .buildAsymmetricDecryptor();

        assertEquals(msg, dec.decrypt(encEnum.encrypt(msg)));
        assertEquals(msg, dec.decrypt(encStr.encrypt(msg)));
    }

    @Test
    void asymmetricByKeyBuilderAcceptsEnumAlgorithm() {
        var keyPair = keyPair("RSA", 2048);

        var encryptor = Bruce.cipherBuilder()
                .keys(Map.of("pub", keyPair.getPublic()))
                .algorithm(AsymmetricAlgorithm.RSA_ECB_PKCS1)
                .buildAsymmetricEncryptorByKey();
        var decryptor = Bruce.cipherBuilder()
                .key(keyPair.getPrivate())
                .algorithm(AsymmetricAlgorithm.RSA_ECB_PKCS1)
                .buildAsymmetricDecryptor();

        Bytes msg = Bytes.from("by-key-asymmetric-enum");
        assertEquals(msg, decryptor.decrypt(encryptor.encrypt("pub", msg)));
    }

    // ── AlgorithmId interface ────────────────────────────────────────────────

    @Test
    void allEnumsImplementAlgorithmId() {
        for (DigestAlgorithm a : DigestAlgorithm.values()) {
            assertInstanceOf(AlgorithmId.class, a);
        }
        for (MacAlgorithm a : MacAlgorithm.values()) {
            assertInstanceOf(AlgorithmId.class, a);
        }
        for (SignatureAlgorithm a : SignatureAlgorithm.values()) {
            assertInstanceOf(AlgorithmId.class, a);
        }
        for (SymmetricAlgorithm a : SymmetricAlgorithm.values()) {
            assertInstanceOf(AlgorithmId.class, a);
        }
        for (SymmetricCipherAlgorithm a : SymmetricCipherAlgorithm.values()) {
            assertInstanceOf(AlgorithmId.class, a);
        }
        for (AsymmetricAlgorithm a : AsymmetricAlgorithm.values()) {
            assertInstanceOf(AlgorithmId.class, a);
        }
    }
}
