package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.Bytes;
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
     */
    public CipherBuilder key(Bytes key) {
        this.symmetricKey = key;
        return this;
    }

    /** Sets the symmetric cipher key as raw bytes. */
    public CipherBuilder key(byte[] key) {
        this.symmetricKey = Bytes.from(key);
        return this;
    }

    /** Sets the asymmetric cipher key. */
    public CipherBuilder key(Key key) {
        this.asymmetricKey = key;
        return this;
    }

    /** Sets a map of asymmetric keys for runtime key selection. */
    public CipherBuilder keys(Map<String, Key> keys) {
        this.asymmetricKeys = keys;
        return this;
    }

    /** Sets the key algorithm for symmetric ciphers (e.g., {@code "AES"}). */
    public CipherBuilder keyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        return this;
    }

    /** Sets the cipher algorithm (e.g., {@code "AES/CBC/PKCS5Padding"}, {@code "RSA"}). */
    public CipherBuilder algorithm(String cipherAlgorithm) {
        this.cipherAlgorithm = cipherAlgorithm;
        return this;
    }

    /** Sets both key and cipher algorithms (convenience method). */
    public CipherBuilder algorithms(String keyAlgorithm, String cipherAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        this.cipherAlgorithm = cipherAlgorithm;
        return this;
    }

    /** Sets the cryptographic provider (e.g., {@code "BC"} for Bouncy Castle). */
    public CipherBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }

    public SymmetricEncryptor buildSymmetricEncryptor() {
        validateFixedSymmetricCipher();
        return SymmetricCipherOperations.createEncryptor(symmetricKey.asBytes(), keyAlgorithm, cipherAlgorithm, provider);
    }

    public SymmetricDecryptor buildSymmetricDecryptor() {
        validateFixedSymmetricCipher();
        return SymmetricCipherOperations.createDecryptor(symmetricKey.asBytes(), keyAlgorithm, cipherAlgorithm, provider);
    }

    public SymmetricEncryptorByKey buildSymmetricEncryptorByKey() {
        validateSymmetricByKeyCipher();
        return SymmetricCipherOperations.createEncryptorByKey(keyAlgorithm, cipherAlgorithm, provider);
    }

    public SymmetricDecryptorByKey buildSymmetricDecryptorByKey() {
        validateSymmetricByKeyCipher();
        return SymmetricCipherOperations.createDecryptorByKey(keyAlgorithm, cipherAlgorithm, provider);
    }

    public AsymmetricEncryptor buildAsymmetricEncryptor() {
        validateAsymmetricCipher();
        return AsymmetricCipherOperations.createEncryptor(asymmetricKey, cipherAlgorithm, provider);
    }

    public AsymmetricDecryptor buildAsymmetricDecryptor() {
        validateAsymmetricCipher();
        return AsymmetricCipherOperations.createDecryptor(asymmetricKey, cipherAlgorithm, provider);
    }

    public AsymmetricEncryptorByKey buildAsymmetricEncryptorByKey() {
        validateAsymmetricByKeyCipher();
        return AsymmetricCipherOperations.createEncryptorByKey(asymmetricKeys, cipherAlgorithm, provider);
    }

    public AsymmetricDecryptorByKey buildAsymmetricDecryptorByKey() {
        validateAsymmetricByKeyCipher();
        return AsymmetricCipherOperations.createDecryptorByKey(asymmetricKeys, cipherAlgorithm, provider);
    }

    private void validateFixedSymmetricCipher() {
        if (symmetricKey == null) throw new BruceException("key is required for symmetric cipher");
        if (keyAlgorithm == null) throw new BruceException("keyAlgorithm is required for symmetric cipher");
        if (cipherAlgorithm == null) throw new BruceException("cipherAlgorithm is required for symmetric cipher");
    }

    private void validateAsymmetricCipher() {
        if (asymmetricKey == null) throw new BruceException("key is required for asymmetric cipher");
        if (cipherAlgorithm == null) throw new BruceException("algorithm is required for asymmetric cipher");
    }

    private void validateSymmetricByKeyCipher() {
        if (keyAlgorithm == null) throw new BruceException("keyAlgorithm is required for symmetric by-key cipher");
        if (cipherAlgorithm == null) throw new BruceException("cipherAlgorithm is required for symmetric by-key cipher");
    }

    private void validateAsymmetricByKeyCipher() {
        if (asymmetricKeys == null || asymmetricKeys.isEmpty()) throw new BruceException("keys are required for asymmetric by-key cipher");
        if (cipherAlgorithm == null) throw new BruceException("algorithm is required for asymmetric by-key cipher");
    }
}
