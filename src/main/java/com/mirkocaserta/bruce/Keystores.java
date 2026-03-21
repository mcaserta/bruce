package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.impl.keystore.KeyGenerators;
import com.mirkocaserta.bruce.impl.keystore.KeyStoreOperations;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;

/**
 * Feature-focused facade for keystore and key-management operations.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class Keystores {

    /** Default keystore type used by Bruce when none is explicitly specified. */
    public static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

    private Keystores() {
        // utility class
    }

    /**
     * Loads an empty default-type keystore.
     *
     * @return loaded keystore instance
     */
    public static KeyStore keystore() {
        return KeyStoreOperations.loadDefaultKeyStore();
    }

    /**
     * Loads an empty keystore of the given type.
     *
     * @param type keystore type (for example {@code PKCS12} or {@code JKS})
     * @return loaded keystore instance
     */
    public static KeyStore keystore(String type) {
        return KeyStoreOperations.loadKeyStore(type);
    }

    /**
     * Loads a keystore from a location using the default keystore type.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, char[] password) {
        return KeyStoreOperations.loadKeyStore(location, password);
    }

    /**
     * Loads a keystore from a location using the default keystore type.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, String password) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray());
    }

    /**
     * Loads a keystore from a location with explicit type.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @param type keystore type
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, char[] password, String type) {
        return KeyStoreOperations.loadKeyStore(location, password, type);
    }

    /**
     * Loads a keystore from a location with explicit type.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @param type keystore type
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, String password, String type) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray(), type);
    }

    /**
     * Loads a keystore from a location with explicit type and provider.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @param type keystore type
     * @param provider provider name, or empty for default
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, char[] password, String type, String provider) {
        return KeyStoreOperations.loadKeyStore(location, password, type, provider);
    }

    /**
     * Loads a keystore from a location with explicit type and provider.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @param type keystore type
     * @param provider provider name, or empty for default
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, String password, String type, String provider) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray(), type, provider);
    }

    /**
     * Loads a certificate by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias certificate alias
     * @return certificate instance
     */
    public static Certificate certificate(KeyStore keystore, String alias) {
        return KeyStoreOperations.loadCertificate(keystore, alias);
    }

    /**
     * Extracts a public key by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias key alias
     * @return public key
     */
    public static PublicKey publicKey(KeyStore keystore, String alias) {
        return KeyStoreOperations.extractPublicKey(keystore, alias);
    }

    /**
     * Loads a private key by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias key alias
     * @param password private key password
     * @return private key
     */
    public static PrivateKey privateKey(KeyStore keystore, String alias, String password) {
        return KeyStoreOperations.loadPrivateKey(keystore, alias, password.toCharArray());
    }

    /**
     * Loads a private key by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias key alias
     * @param password private key password
     * @return private key
     */
    public static PrivateKey privateKey(KeyStore keystore, String alias, char[] password) {
        return KeyStoreOperations.loadPrivateKey(keystore, alias, password);
    }

    /**
     * Loads a secret key by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias key alias
     * @param password secret key password
     * @return secret key
     */
    public static Key secretKey(KeyStore keystore, String alias, String password) {
        return KeyStoreOperations.loadSecretKey(keystore, alias, password.toCharArray());
    }

    /**
     * Loads a secret key by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias key alias
     * @param password secret key password
     * @return secret key
     */
    public static Key secretKey(KeyStore keystore, String alias, char[] password) {
        return KeyStoreOperations.loadSecretKey(keystore, alias, password);
    }

    /**
     * Generates a key pair.
     *
     * @param algorithm key pair algorithm (for example {@code RSA} or {@code DSA})
     * @param keySize key size in bits
     * @return generated key pair
     */
    public static KeyPair keyPair(String algorithm, int keySize) {
        return KeyGenerators.generateKeyPair(algorithm, keySize);
    }

    /**
     * Generates a key pair with explicit provider.
     *
     * @param algorithm key pair algorithm
     * @param provider provider name
     * @param keySize key size in bits
     * @return generated key pair
     */
    public static KeyPair keyPair(String algorithm, String provider, int keySize) {
        return KeyGenerators.generateKeyPair(algorithm, provider, keySize);
    }

    /**
     * Generates a key pair using the given secure random source.
     *
     * @param algorithm key pair algorithm
     * @param keySize key size in bits
     * @param random secure random source
     * @return generated key pair
     */
    public static KeyPair keyPair(String algorithm, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithm, keySize, random);
    }

    /**
     * Generates a key pair with explicit provider and secure random source.
     *
     * @param algorithm key pair algorithm
     * @param provider provider name
     * @param keySize key size in bits
     * @param random secure random source
     * @return generated key pair
     */
    public static KeyPair keyPair(String algorithm, String provider, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithm, provider, keySize, random);
    }

    /**
     * Generates a random symmetric key.
     *
     * @param algorithm key algorithm (for example {@code AES})
     * @return raw symmetric key bytes
     */
    public static byte[] symmetricKey(String algorithm) {
        return KeyGenerators.generateSymmetricKey(algorithm);
    }

    /**
     * Generates a random symmetric key with explicit provider.
     *
     * @param algorithm key algorithm
     * @param provider provider name
     * @return raw symmetric key bytes
     */
    public static byte[] symmetricKey(String algorithm, String provider) {
        return KeyGenerators.generateSymmetricKey(algorithm, provider);
    }

    /**
     * Generates a random symmetric key and encodes it.
     *
     * @param algorithm key algorithm
     * @param encoding output encoding
     * @return encoded key text
     */
    public static String symmetricKey(String algorithm, Bruce.Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithm, encoding);
    }

    /**
     * Generates a random symmetric key with explicit provider and encodes it.
     *
     * @param algorithm key algorithm
     * @param provider provider name
     * @param encoding output encoding
     * @return encoded key text
     */
    public static String symmetricKey(String algorithm, String provider, Bruce.Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithm, provider, encoding);
    }
}

