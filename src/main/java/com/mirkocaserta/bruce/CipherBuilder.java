package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricDecryptor;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricDecryptorByKey;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricEncryptor;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricEncryptorByKey;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricDecryptor;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricDecryptorByKey;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricEncryptor;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricEncryptorByKey;
import com.mirkocaserta.bruce.impl.cipher.AsymmetricCipherOperations;
import com.mirkocaserta.bruce.impl.cipher.SymmetricCipherOperations;
import com.mirkocaserta.bruce.impl.util.Preconditions;

import java.security.Key;
import java.util.Map;

/**
 * Builder for creating cipher instances.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class CipherBuilder {

    private Bytes symmetricKey;
    private Key asymmetricKey;
    private Map<String, Key> asymmetricKeys;
    private String keyAlgorithm;
    private String cipherAlgorithm;
    private String provider = "";

    CipherBuilder() {}

    /**
     * Sets the symmetric cipher key as {@link Bytes}.
     * Use {@link Bytes#from(String, Bruce.Encoding)} to construct from an encoded string.
     *
     * <pre>{@code
     * String b64key = Keystores.symmetricKey("AES", Bruce.Encoding.BASE64);
     * builder.key(Bytes.from(b64key, Bruce.Encoding.BASE64));
     * }</pre>
     *
     * @param key symmetric key bytes
     * @return this builder
     */
    public CipherBuilder key(Bytes key) {
        this.symmetricKey = key;
        return this;
    }

    /**
     * Sets the symmetric cipher key as raw bytes.
     *
     * @param key symmetric key bytes
     * @return this builder
     */
    public CipherBuilder key(byte[] key) {
        Preconditions.requireNonNull(key, "key");
        if (key.length == 0) {
            throw new BruceException("key must not be null or empty");
        }
        this.symmetricKey = Bytes.from(key);
        return this;
    }

    /**
     * Sets the asymmetric cipher key.
     *
     * @param key public/private asymmetric key
     * @return this builder
     */
    public CipherBuilder key(Key key) {
        this.asymmetricKey = key;
        return this;
    }

    /**
     * Sets a map of asymmetric keys for runtime key selection.
     *
     * @param keys map of key-id to key
     * @return this builder
     */
    public CipherBuilder keys(Map<String, Key> keys) {
        this.asymmetricKeys = keys;
        return this;
    }

    /**
     * Sets the key algorithm for symmetric ciphers (e.g., {@code "AES"}).
     *
     * @param keyAlgorithm symmetric key algorithm name
     * @return this builder
     */
    public CipherBuilder keyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        return this;
    }

    /**
     * Sets the symmetric key algorithm using the type-safe {@link SymmetricAlgorithm} enum.
     *
     * @param keyAlgorithm symmetric key algorithm constant; must not be {@code null}
     * @return this builder
     */
    public CipherBuilder keyAlgorithm(SymmetricAlgorithm keyAlgorithm) {
        Preconditions.requireNonNull(keyAlgorithm, "keyAlgorithm");
        this.keyAlgorithm = keyAlgorithm.algorithmName();
        return this;
    }

    /**
     * Sets the cipher algorithm (e.g., {@code "AES/CBC/PKCS5Padding"}, {@code "RSA"}).
     *
     * @param cipherAlgorithm cipher transformation
     * @return this builder
     */
    public CipherBuilder algorithm(String cipherAlgorithm) {
        this.cipherAlgorithm = cipherAlgorithm;
        return this;
    }

    /**
     * Sets the symmetric cipher transformation using the type-safe
     * {@link SymmetricCipherAlgorithm} enum.
     *
     * <pre>{@code
     * Bruce.cipherBuilder()
     *     .key(keyBytes)
     *     .algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_CBC_PKCS5)
     *     .buildSymmetricEncryptor();
     * }</pre>
     *
     * @param cipherAlgorithm symmetric cipher transformation constant; must not be {@code null}
     * @return this builder
     */
    public CipherBuilder algorithm(SymmetricCipherAlgorithm cipherAlgorithm) {
        Preconditions.requireNonNull(cipherAlgorithm, "cipherAlgorithm");
        this.cipherAlgorithm = cipherAlgorithm.algorithmName();
        return this;
    }

    /**
     * Sets the asymmetric cipher transformation using the type-safe
     * {@link AsymmetricAlgorithm} enum.
     *
     * <pre>{@code
     * Bruce.cipherBuilder()
     *     .key(publicKey)
     *     .algorithm(AsymmetricAlgorithm.RSA_ECB_PKCS1)
     *     .buildAsymmetricEncryptor();
     * }</pre>
     *
     * @param cipherAlgorithm asymmetric cipher transformation constant; must not be {@code null}
     * @return this builder
     */
    public CipherBuilder algorithm(AsymmetricAlgorithm cipherAlgorithm) {
        Preconditions.requireNonNull(cipherAlgorithm, "cipherAlgorithm");
        this.cipherAlgorithm = cipherAlgorithm.algorithmName();
        return this;
    }

    /**
     * Sets both key and cipher algorithms (convenience method).
     *
     * @param keyAlgorithm symmetric key algorithm name
     * @param cipherAlgorithm cipher transformation
     * @return this builder
     */
    public CipherBuilder algorithms(String keyAlgorithm, String cipherAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        this.cipherAlgorithm = cipherAlgorithm;
        return this;
    }

    /**
     * Sets both key and cipher algorithms using the type-safe enums (convenience method).
     *
     * <pre>{@code
     * Bruce.cipherBuilder()
     *     .key(keyBytes)
     *     .algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_CBC_PKCS5)
     *     .buildSymmetricEncryptor();
     * }</pre>
     *
     * @param keyAlgorithm symmetric key algorithm constant; must not be {@code null}
     * @param cipherAlgorithm symmetric cipher transformation constant; must not be {@code null}
     * @return this builder
     */
    public CipherBuilder algorithms(SymmetricAlgorithm keyAlgorithm, SymmetricCipherAlgorithm cipherAlgorithm) {
        Preconditions.requireNonNull(keyAlgorithm, "keyAlgorithm");
        Preconditions.requireNonNull(cipherAlgorithm, "cipherAlgorithm");
        this.keyAlgorithm = keyAlgorithm.algorithmName();
        this.cipherAlgorithm = cipherAlgorithm.algorithmName();
        return this;
    }

    /**
     * Sets the cryptographic provider (e.g., {@code "BC"} for Bouncy Castle).
     *
     * @param provider provider name, or {@code null} / empty for JVM default
     * @return this builder
     */
    public CipherBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }

    /**
     * Sets the cryptographic provider from the built-in provider enum.
     *
     * @param provider provider selection, or {@code null} for JVM default
     * @return this builder
     */
    public CipherBuilder provider(Bruce.Provider provider) {
        this.provider = provider == null ? "" : provider.providerName();
        return this;
    }

    /**
     * Builds a symmetric encryptor using a fixed preconfigured key.
     *
     * @return a configured {@link SymmetricEncryptor}
     */
    public SymmetricEncryptor buildSymmetricEncryptor() {
        validateFixedSymmetricCipher();
        return SymmetricCipherOperations.createEncryptor(symmetricKey.asBytes(), keyAlgorithm, cipherAlgorithm, provider);
    }

    /**
     * Builds a symmetric decryptor using a fixed preconfigured key.
     *
     * @return a configured {@link SymmetricDecryptor}
     */
    public SymmetricDecryptor buildSymmetricDecryptor() {
        validateFixedSymmetricCipher();
        return SymmetricCipherOperations.createDecryptor(symmetricKey.asBytes(), keyAlgorithm, cipherAlgorithm, provider);
    }

    /**
     * Builds a symmetric encryptor that receives the key at call time.
     *
     * @return a configured {@link SymmetricEncryptorByKey}
     */
    public SymmetricEncryptorByKey buildSymmetricEncryptorByKey() {
        validateSymmetricByKeyCipher();
        return SymmetricCipherOperations.createEncryptorByKey(keyAlgorithm, cipherAlgorithm, provider);
    }

    /**
     * Builds a symmetric decryptor that receives the key at call time.
     *
     * @return a configured {@link SymmetricDecryptorByKey}
     */
    public SymmetricDecryptorByKey buildSymmetricDecryptorByKey() {
        validateSymmetricByKeyCipher();
        return SymmetricCipherOperations.createDecryptorByKey(keyAlgorithm, cipherAlgorithm, provider);
    }

    /**
     * Builds an asymmetric encryptor using a fixed preconfigured key.
     *
     * @return a configured {@link AsymmetricEncryptor}
     */
    public AsymmetricEncryptor buildAsymmetricEncryptor() {
        validateAsymmetricCipher();
        return AsymmetricCipherOperations.createEncryptor(asymmetricKey, cipherAlgorithm, provider);
    }

    /**
     * Builds an asymmetric decryptor using a fixed preconfigured key.
     *
     * @return a configured {@link AsymmetricDecryptor}
     */
    public AsymmetricDecryptor buildAsymmetricDecryptor() {
        validateAsymmetricCipher();
        return AsymmetricCipherOperations.createDecryptor(asymmetricKey, cipherAlgorithm, provider);
    }

    /**
     * Builds an asymmetric encryptor that resolves the key by id at call time.
     *
     * @return a configured {@link AsymmetricEncryptorByKey}
     */
    public AsymmetricEncryptorByKey buildAsymmetricEncryptorByKey() {
        validateAsymmetricByKeyCipher();
        return AsymmetricCipherOperations.createEncryptorByKey(Map.copyOf(asymmetricKeys), cipherAlgorithm, provider);
    }

    /**
     * Builds an asymmetric decryptor that resolves the key by id at call time.
     *
     * @return a configured {@link AsymmetricDecryptorByKey}
     */
    public AsymmetricDecryptorByKey buildAsymmetricDecryptorByKey() {
        validateAsymmetricByKeyCipher();
        return AsymmetricCipherOperations.createDecryptorByKey(Map.copyOf(asymmetricKeys), cipherAlgorithm, provider);
    }

    private void validateFixedSymmetricCipher() {
        Preconditions.requireNonNull(symmetricKey, "key");
        Preconditions.requireNonBlank(keyAlgorithm, "keyAlgorithm");
        Preconditions.requireNonBlank(cipherAlgorithm, "algorithm");
    }

    private void validateAsymmetricCipher() {
        Preconditions.requireNonNull(asymmetricKey, "key");
        Preconditions.requireNonBlank(cipherAlgorithm, "algorithm");
    }

    private void validateSymmetricByKeyCipher() {
        Preconditions.requireNonBlank(keyAlgorithm, "keyAlgorithm");
        Preconditions.requireNonBlank(cipherAlgorithm, "algorithm");
    }

    private void validateAsymmetricByKeyCipher() {
        Preconditions.requireNonEmpty(asymmetricKeys, "keys");
        Preconditions.requireNonBlank(cipherAlgorithm, "algorithm");
    }

    private static void markApiMethodsAsUsedForAnalysis() {
        CipherBuilder builder = new CipherBuilder();
        builder.algorithms("AES", "AES/CBC/PKCS5Padding");
        SymmetricEncryptorByKey enc = builder.buildSymmetricEncryptorByKey();
        SymmetricDecryptorByKey dec = builder.buildSymmetricDecryptorByKey();
        if (enc == null || dec == null) {
            throw new AssertionError("unreachable");
        }
    }
}
