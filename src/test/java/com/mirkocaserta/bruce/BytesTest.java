package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;

import static com.mirkocaserta.bruce.Keystores.*;
import static org.junit.jupiter.api.Assertions.*;

class BytesTest {

    // ── Construction ─────────────────────────────────────────────────────────

    @Test
    void fromRawBytes() {
        byte[] raw = {0, 1, 2, 3};
        Bytes b = Bytes.from(raw);
        assertArrayEquals(raw, b.asBytes());
    }

    @Test
    void fromRawBytesMakesDefensiveCopy() {
        byte[] raw = {1, 2, 3};
        Bytes b = Bytes.from(raw);
        raw[0] = 99;
        assertEquals(1, b.asBytes()[0], "construction should copy bytes");
    }

    @Test
    void asBytesMakesDefensiveCopy() {
        Bytes b = Bytes.from(new byte[]{1, 2, 3});
        byte[] out = b.asBytes();
        out[0] = 99;
        assertEquals(1, b.asBytes()[0], "asBytes() should return a copy");
    }

    @Test
    void fromUtf8String() {
        Bytes b = Bytes.from("Hello");
        assertArrayEquals("Hello".getBytes(StandardCharsets.UTF_8), b.asBytes());
    }

    @Test
    void fromStringWithExplicitCharset() {
        Bytes b = Bytes.from("Hello", StandardCharsets.ISO_8859_1);
        assertArrayEquals("Hello".getBytes(StandardCharsets.ISO_8859_1), b.asBytes());
    }

    @Test
    void fromBase64EncodedString() {
        byte[] original = {10, 20, 30, 40};
        String encoded = Base64.getEncoder().encodeToString(original);
        Bytes b = Bytes.from(encoded, Bruce.Encoding.BASE64);
        assertArrayEquals(original, b.asBytes());
    }

    @Test
    void fromHexEncodedString() {
        Bytes b = Bytes.from("0a141e28", Bruce.Encoding.HEX);
        assertArrayEquals(new byte[]{10, 20, 30, 40}, b.asBytes());
    }

    @Test
    void fromUrlEncodedString() {
        byte[] original = {(byte) 0xFB, (byte) 0xFF};
        String urlEncoded = Base64.getUrlEncoder().encodeToString(original);
        Bytes b = Bytes.from(urlEncoded, Bruce.Encoding.URL);
        assertArrayEquals(original, b.asBytes());
    }

    @Test
    void fromMimeEncodedString() {
        byte[] original = new byte[100];
        new SecureRandom().nextBytes(original);
        String mimeEncoded = Base64.getMimeEncoder().encodeToString(original);
        Bytes b = Bytes.from(mimeEncoded, Bruce.Encoding.MIME);
        assertArrayEquals(original, b.asBytes());
    }

    @Test
    void fromFilePath(@TempDir Path tempDir) throws IOException {
        byte[] content = {7, 8, 9};
        Path file = tempDir.resolve("test.bin");
        Files.write(file, content);
        Bytes b = Bytes.fromFile(file);
        assertArrayEquals(content, b.asBytes());
    }

    @Test
    void fromFileObject(@TempDir Path tempDir) throws IOException {
        byte[] content = {4, 5, 6};
        Path file = tempDir.resolve("test2.bin");
        Files.write(file, content);
        Bytes b = Bytes.fromFile(file.toFile());
        assertArrayEquals(content, b.asBytes());
    }

    @Test
    void fromFileThrowsOnMissingFile(@TempDir Path tempDir) {
        assertThrows(BruceException.class, () -> Bytes.fromFile(tempDir.resolve("missing.bin")));
    }

    // ── Null guards ──────────────────────────────────────────────────────────

    @Test
    void nullBytesArrayThrows() {
        assertThrows(NullPointerException.class, () -> Bytes.from((byte[]) null));
    }

    @Test
    void nullStringThrows() {
        assertThrows(NullPointerException.class, () -> Bytes.from((String) null));
    }

    @Test
    void nullStringWithCharsetThrows() {
        assertThrows(NullPointerException.class, () -> Bytes.from(null, StandardCharsets.UTF_8));
    }

    @Test
    void nullCharsetThrows() {
        assertThrows(NullPointerException.class, () -> Bytes.from("hello", (java.nio.charset.Charset) null));
    }

    @Test
    void nullEncodedStringThrows() {
        assertThrows(NullPointerException.class, () -> Bytes.from(null, Bruce.Encoding.BASE64));
    }

    @Test
    void nullEncodingThrows() {
        assertThrows(NullPointerException.class, () -> Bytes.from("abc", (Bruce.Encoding) null));
    }

    @Test
    void nullFilePathThrows() {
        assertThrows(NullPointerException.class, () -> Bytes.fromFile((Path) null));
    }

    @Test
    void nullFileThrows() {
        assertThrows(NullPointerException.class, () -> Bytes.fromFile((java.io.File) null));
    }

    // ── Views ────────────────────────────────────────────────────────────────

    @Test
    void encodeToBase64() {
        byte[] raw = {10, 20, 30};
        String expected = Base64.getEncoder().encodeToString(raw);
        assertEquals(expected, Bytes.from(raw).encode(Bruce.Encoding.BASE64));
    }

    @Test
    void encodeToHex() {
        assertEquals("0a141e", Bytes.from(new byte[]{10, 20, 30}).encode(Bruce.Encoding.HEX));
    }

    @Test
    void asStringDefaultsToUtf8() {
        assertEquals("Hello", Bytes.from("Hello").asString());
    }

    @Test
    void asStringWithExplicitCharset() {
        byte[] latin1Bytes = "café".getBytes(StandardCharsets.ISO_8859_1);
        assertEquals("café", Bytes.from(latin1Bytes).asString(StandardCharsets.ISO_8859_1));
    }

    @Test
    void isEmpty() {
        assertTrue(Bytes.from(new byte[0]).isEmpty());
        assertFalse(Bytes.from(new byte[]{1}).isEmpty());
    }

    @Test
    void length() {
        assertEquals(3, Bytes.from(new byte[]{1, 2, 3}).length());
        assertEquals(0, Bytes.from(new byte[0]).length());
    }

    @Test
    void encodeNullEncodingThrows() {
        assertThrows(NullPointerException.class, () -> Bytes.from("x").encode(null));
    }

    // ── Object contract ──────────────────────────────────────────────────────

    @Test
    void equalInstancesHaveSameHashCode() {
        Bytes a = Bytes.from("Hello");
        Bytes b = Bytes.from("Hello");
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void differentContentIsNotEqual() {
        assertNotEquals(Bytes.from("Hello"), Bytes.from("World"));
    }

    @Test
    void reflexiveEquality() {
        Bytes b = Bytes.from("test");
        assertEquals(b, b);
    }

    @Test
    void notEqualToNull() {
        assertNotEquals(null, Bytes.from("test"));
    }

    @Test
    void notEqualToOtherType() {
        assertNotEquals("hello", Bytes.from("hello"));
    }

    @Test
    void toStringDoesNotLeakContent() {
        String s = Bytes.from("super secret data").toString();
        assertFalse(s.contains("super"), "toString() must not expose content");
        assertTrue(s.startsWith("Bytes["));
        assertTrue(s.contains(String.valueOf("super secret data".getBytes(StandardCharsets.UTF_8).length)));
    }

    // ── Integration with crypto interfaces ───────────────────────────────────

    @Test
    void bytesWithSigner() {
        KeyPair kp = keyPair("RSA", 2048);
        var signer = Bruce.signerBuilder().key(kp.getPrivate()).algorithm("SHA256withRSA").build();
        var verifier = Bruce.verifierBuilder().key(kp.getPublic()).algorithm("SHA256withRSA").build();

        Bytes message = Bytes.from("Hello, Bytes!");
        Bytes signature = signer.sign(message);

        assertNotNull(signature);
        assertFalse(signature.isEmpty());
        assertTrue(verifier.verify(message, signature));
        // round-trip: re-wrap from BASE64
        assertTrue(verifier.verify(message, Bytes.from(signature.encode(Bruce.Encoding.BASE64), Bruce.Encoding.BASE64)));
    }

    @Test
    void bytesWithDigester() {
        var digester = Bruce.digestBuilder().algorithm("SHA-256").build();

        Bytes input = Bytes.from("hello");
        Bytes digest = digester.digest(input);

        assertNotNull(digest);
        assertEquals(32, digest.length(), "SHA-256 digest is always 32 bytes");
        // deterministic: same input produces same digest
        assertEquals(digest, digester.digest(Bytes.from("hello")));
    }

    @Test
    void bytesWithMac() {
        var keyStore = Keystores.keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        var secretKey = secretKey(keyStore, "hmac", "password".toCharArray());
        var mac = Bruce.macBuilder().key(secretKey).algorithm("HmacSHA1").build();

        Bytes input = Bytes.from("payload");
        Bytes result = mac.get(input);

        assertNotNull(result);
        assertFalse(result.isEmpty());
        // deterministic: same input produces same MAC
        assertEquals(result, mac.get(Bytes.from("payload")));
    }

    @Test
    void bytesWithAsymmetricCipher() {
        KeyPair kp = keyPair("RSA", 2048);
        var encryptor = Bruce.cipherBuilder().key(kp.getPublic()).algorithm("RSA").buildAsymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder().key(kp.getPrivate()).algorithm("RSA").buildAsymmetricDecryptor();

        Bytes plaintext = Bytes.from("secret message");
        Bytes ciphertext = encryptor.encrypt(plaintext);
        Bytes recovered = decryptor.decrypt(ciphertext);

        assertEquals("secret message", recovered.asString());
    }

    @Test
    void bytesWithSymmetricCipher() {
        byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(ivBytes);
        Bytes iv  = Bytes.from(ivBytes);
        Bytes key = Bytes.from(symmetricKey("AES", Bruce.Encoding.BASE64), Bruce.Encoding.BASE64);

        var encryptor = Bruce.cipherBuilder()
                .key(key).keyAlgorithm("AES").algorithm("AES/CBC/PKCS5Padding")
                .buildSymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder()
                .key(key).keyAlgorithm("AES").algorithm("AES/CBC/PKCS5Padding")
                .buildSymmetricDecryptor();

        Bytes plaintext = Bytes.from("Hello symmetric Bytes!");
        Bytes ciphertext = encryptor.encrypt(iv, plaintext);
        Bytes recovered = decryptor.decrypt(iv, ciphertext);

        assertEquals("Hello symmetric Bytes!", recovered.asString());
    }

    @Test
    void bytesRoundTripThroughEncodings() {
        byte[] original = new byte[32];
        new SecureRandom().nextBytes(original);
        Bytes b = Bytes.from(original);

        assertArrayEquals(original, Bytes.from(b.encode(Bruce.Encoding.BASE64), Bruce.Encoding.BASE64).asBytes());
        assertArrayEquals(original, Bytes.from(b.encode(Bruce.Encoding.HEX),    Bruce.Encoding.HEX).asBytes());
        assertArrayEquals(original, Bytes.from(b.encode(Bruce.Encoding.URL),    Bruce.Encoding.URL).asBytes());
        assertArrayEquals(original, Bytes.from(b.encode(Bruce.Encoding.MIME),   Bruce.Encoding.MIME).asBytes());
    }
}

