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

    public static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

    private Keystores() {
        // utility class
    }

    public static KeyStore keystore() {
        return KeyStoreOperations.loadDefaultKeyStore();
    }

    public static KeyStore keystore(String type) {
        return KeyStoreOperations.loadKeyStore(type);
    }

    public static KeyStore keystore(String location, char[] password) {
        return KeyStoreOperations.loadKeyStore(location, password);
    }

    public static KeyStore keystore(String location, String password) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray());
    }

    public static KeyStore keystore(String location, char[] password, String type) {
        return KeyStoreOperations.loadKeyStore(location, password, type);
    }

    public static KeyStore keystore(String location, String password, String type) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray(), type);
    }

    public static KeyStore keystore(String location, char[] password, String type, String provider) {
        return KeyStoreOperations.loadKeyStore(location, password, type, provider);
    }

    public static KeyStore keystore(String location, String password, String type, String provider) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray(), type, provider);
    }

    public static Certificate certificate(KeyStore keystore, String alias) {
        return KeyStoreOperations.loadCertificate(keystore, alias);
    }

    public static PublicKey publicKey(KeyStore keystore, String alias) {
        return KeyStoreOperations.extractPublicKey(keystore, alias);
    }

    public static PrivateKey privateKey(KeyStore keystore, String alias, String password) {
        return KeyStoreOperations.loadPrivateKey(keystore, alias, password.toCharArray());
    }

    public static PrivateKey privateKey(KeyStore keystore, String alias, char[] password) {
        return KeyStoreOperations.loadPrivateKey(keystore, alias, password);
    }

    public static Key secretKey(KeyStore keystore, String alias, String password) {
        return KeyStoreOperations.loadSecretKey(keystore, alias, password.toCharArray());
    }

    public static Key secretKey(KeyStore keystore, String alias, char[] password) {
        return KeyStoreOperations.loadSecretKey(keystore, alias, password);
    }

    public static KeyPair keyPair(String algorithm, int keySize) {
        return KeyGenerators.generateKeyPair(algorithm, keySize);
    }

    public static KeyPair keyPair(String algorithm, String provider, int keySize) {
        return KeyGenerators.generateKeyPair(algorithm, provider, keySize);
    }

    public static KeyPair keyPair(String algorithm, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithm, keySize, random);
    }

    public static KeyPair keyPair(String algorithm, String provider, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithm, provider, keySize, random);
    }

    public static byte[] symmetricKey(String algorithm) {
        return KeyGenerators.generateSymmetricKey(algorithm);
    }

    public static byte[] symmetricKey(String algorithm, String provider) {
        return KeyGenerators.generateSymmetricKey(algorithm, provider);
    }

    public static String symmetricKey(String algorithm, Bruce.Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithm, encoding);
    }

    public static String symmetricKey(String algorithm, String provider, Bruce.Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithm, provider, encoding);
    }
}

