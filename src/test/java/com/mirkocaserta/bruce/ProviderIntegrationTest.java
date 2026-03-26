package com.mirkocaserta.bruce;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.SecureRandom;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.Keystores.keyPair;
import static com.mirkocaserta.bruce.Keystores.symmetricKey;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProviderIntegrationTest {

    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    @ParameterizedTest
    @MethodSource("com.mirkocaserta.bruce.ProviderTestSupport#providers")
    void providersExposeRequiredAlgorithms(Bruce.Provider provider) {
        if (provider == Bruce.Provider.JCA) {
            assertDoesNotThrow(() -> javax.crypto.Cipher.getInstance(RSA_TRANSFORMATION));
            assertDoesNotThrow(() -> javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding"));
            assertDoesNotThrow(() -> Signature.getInstance("SHA256withRSA"));
            assertDoesNotThrow(() -> MessageDigest.getInstance("SHA-256"));
            assertDoesNotThrow(() -> javax.crypto.Mac.getInstance("HmacSHA256"));
            return;
        }

        var jcaProvider = Security.getProvider(provider.providerName());
        assertNotNull(jcaProvider);
        assertDoesNotThrow(() -> javax.crypto.Cipher.getInstance(RSA_TRANSFORMATION, jcaProvider));
        assertDoesNotThrow(() -> javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding", jcaProvider));
        assertDoesNotThrow(() -> Signature.getInstance("SHA256withRSA", jcaProvider));
        assertDoesNotThrow(() -> MessageDigest.getInstance("SHA-256", jcaProvider));
        assertDoesNotThrow(() -> javax.crypto.Mac.getInstance("HmacSHA256", jcaProvider));
    }

    @ParameterizedTest
    @MethodSource("com.mirkocaserta.bruce.ProviderTestSupport#providers")
    void digestBuilderWorksAcrossProviders(Bruce.Provider provider) {
        var digester = Bruce.digestBuilder().algorithm("SHA-256").provider(provider).build();
        Bytes digest = digester.digest(Bytes.from("provider-digest"));

        assertNotNull(digest);
        assertEquals(32, digest.length());
    }

    @ParameterizedTest
    @MethodSource("com.mirkocaserta.bruce.ProviderTestSupport#providers")
    void signerAndVerifierBuildersWorkAcrossProviders(Bruce.Provider provider) {
        var rsa = keyPair("RSA", 2048);

        var signer = Bruce.signerBuilder()
                .key(rsa.getPrivate())
                .algorithm("SHA256withRSA")
                .provider(provider)
                .build();
        var verifier = Bruce.verifierBuilder()
                .key(rsa.getPublic())
                .algorithm("SHA256withRSA")
                .provider(provider)
                .build();

        Bytes message = Bytes.from("provider-signature");
        Bytes signature = signer.sign(message);

        assertFalse(signature.isEmpty());
        assertTrue(verifier.verify(message, signature));
    }

    @ParameterizedTest
    @MethodSource("com.mirkocaserta.bruce.ProviderTestSupport#providers")
    void macBuilderWorksAcrossProviders(Bruce.Provider provider) {
        byte[] keyBytes = symmetricKey("HmacSHA256", provider);
        var key = new SecretKeySpec(keyBytes, "HmacSHA256");

        var mac = Bruce.macBuilder()
                .key(key)
                .algorithm("HmacSHA256")
                .provider(provider)
                .build();

        Bytes result = mac.get(Bytes.from("provider-mac"));

        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @ParameterizedTest
    @MethodSource("com.mirkocaserta.bruce.ProviderTestSupport#providers")
    void symmetricCipherBuilderWorksAcrossProviders(Bruce.Provider provider) {
        byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(ivBytes);

        Bytes iv = Bytes.from(ivBytes);
        Bytes key = Bytes.from(symmetricKey("AES", provider, BASE64), BASE64);
        Bytes plaintext = Bytes.from("provider-symmetric-cipher");

        var encryptor = Bruce.cipherBuilder()
                .key(key)
                .algorithms("AES", "AES/CBC/PKCS5Padding")
                .provider(provider)
                .buildSymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder()
                .key(key)
                .algorithms("AES", "AES/CBC/PKCS5Padding")
                .provider(provider)
                .buildSymmetricDecryptor();

        Bytes ciphertext = encryptor.encrypt(iv, plaintext);
        Bytes decrypted = decryptor.decrypt(iv, ciphertext);

        assertEquals(plaintext, decrypted);
    }

    @ParameterizedTest
    @MethodSource("com.mirkocaserta.bruce.ProviderTestSupport#providers")
    void asymmetricCipherBuilderWorksAcrossProviders(Bruce.Provider provider) {
        var rsa = keyPair("RSA", provider, 2048);

        var encryptor = Bruce.cipherBuilder()
                .key(rsa.getPublic())
                .algorithm(RSA_TRANSFORMATION)
                .provider(provider)
                .buildAsymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder()
                .key(rsa.getPrivate())
                .algorithm(RSA_TRANSFORMATION)
                .provider(provider)
                .buildAsymmetricDecryptor();

        Bytes plaintext = Bytes.from("provider-asymmetric-cipher");
        Bytes ciphertext = encryptor.encrypt(plaintext);
        Bytes decrypted = decryptor.decrypt(ciphertext);

        assertEquals(plaintext, decrypted);
    }
}

