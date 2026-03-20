package com.mirkocaserta.bruce;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;

/**
 * Main backward-compatible facade delegating to feature-focused facades.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class Bruce {

    public static final String DEFAULT_KEYSTORE_TYPE = Keystores.DEFAULT_KEYSTORE_TYPE;

    private Bruce() {
        // utility class
    }

    public static CipherBuilder cipherBuilder() {
        return new CipherBuilder();
    }

    public static SignerBuilder signerBuilder() {
        return new SignerBuilder();
    }

    public static VerifierBuilder verifierBuilder() {
        return new VerifierBuilder();
    }

    public static DigestBuilder digestBuilder() {
        return new DigestBuilder();
    }

    public static MacBuilder macBuilder() {
        return new MacBuilder();
    }

    public static KeyStore keystore() {
        return Keystores.keystore();
    }

    public static KeyStore keystore(String type) {
        return Keystores.keystore(type);
    }

    public static KeyStore keystore(String location, char[] password) {
        return Keystores.keystore(location, password);
    }

    public static KeyStore keystore(String location, String password) {
        return Keystores.keystore(location, password);
    }

    public static KeyStore keystore(String location, char[] password, String type) {
        return Keystores.keystore(location, password, type);
    }

    public static KeyStore keystore(String location, String password, String type) {
        return Keystores.keystore(location, password, type);
    }

    public static KeyStore keystore(String location, char[] password, String type, String provider) {
        return Keystores.keystore(location, password, type, provider);
    }

    public static KeyStore keystore(String location, String password, String type, String provider) {
        return Keystores.keystore(location, password, type, provider);
    }

    public static Certificate certificate(KeyStore keystore, String alias) {
        return Keystores.certificate(keystore, alias);
    }

    public static PublicKey publicKey(KeyStore keystore, String alias) {
        return Keystores.publicKey(keystore, alias);
    }

    public static PrivateKey privateKey(KeyStore keystore, String alias, String password) {
        return Keystores.privateKey(keystore, alias, password);
    }

    public static PrivateKey privateKey(KeyStore keystore, String alias, char[] password) {
        return Keystores.privateKey(keystore, alias, password);
    }

    public static Key secretKey(KeyStore keystore, String alias, String password) {
        return Keystores.secretKey(keystore, alias, password);
    }

    public static Key secretKey(KeyStore keystore, String alias, char[] password) {
        return Keystores.secretKey(keystore, alias, password);
    }

    public static KeyPair keyPair(String algorithm, int keySize) {
        return Keystores.keyPair(algorithm, keySize);
    }

    public static KeyPair keyPair(String algorithm, String provider, int keySize) {
        return Keystores.keyPair(algorithm, provider, keySize);
    }

    public static KeyPair keyPair(String algorithm, int keySize, SecureRandom random) {
        return Keystores.keyPair(algorithm, keySize, random);
    }

    public static KeyPair keyPair(String algorithm, String provider, int keySize, SecureRandom random) {
        return Keystores.keyPair(algorithm, provider, keySize, random);
    }


    public static byte[] symmetricKey(String algorithm) {
        return Keystores.symmetricKey(algorithm);
    }

    public static byte[] symmetricKey(String algorithm, String provider) {
        return Keystores.symmetricKey(algorithm, provider);
    }

    public static String symmetricKey(String algorithm, Encoding encoding) {
        return Keystores.symmetricKey(algorithm, encoding);
    }

    public static String symmetricKey(String algorithm, String provider, Encoding encoding) {
        return Keystores.symmetricKey(algorithm, provider, encoding);
    }



    public enum Encoding {
        HEX,
        BASE64,
        URL,
        MIME
    }
}
