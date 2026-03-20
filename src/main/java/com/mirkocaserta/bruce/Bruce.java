package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.Mode;
import com.mirkocaserta.bruce.cipher.asymmetric.Cipher;
import com.mirkocaserta.bruce.cipher.symmetric.CipherByKey;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipher;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipherByKey;
import com.mirkocaserta.bruce.signature.EncodingSigner;
import com.mirkocaserta.bruce.signature.EncodingSignerByKey;
import com.mirkocaserta.bruce.signature.EncodingVerifier;
import com.mirkocaserta.bruce.signature.EncodingVerifierByKey;
import com.mirkocaserta.bruce.signature.Signer;
import com.mirkocaserta.bruce.signature.SignerByKey;
import com.mirkocaserta.bruce.signature.Verifier;
import com.mirkocaserta.bruce.signature.VerifierByKey;

import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Map;

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

    public static Signer signer(PrivateKey privateKey, String algorithm) {
        return Signatures.signer(privateKey, algorithm);
    }

    public static Signer signer(PrivateKey privateKey, String algorithm, String provider) {
        return Signatures.signer(privateKey, algorithm, provider);
    }

    public static SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm) {
        return Signatures.signer(privateKeyMap, algorithm);
    }

    public static SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider) {
        return Signatures.signer(privateKeyMap, algorithm, provider);
    }

    public static EncodingSignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, Encoding encoding) {
        return Signatures.signer(privateKeyMap, algorithm, encoding);
    }

    public static EncodingSignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, Charset charset, Encoding encoding) {
        return Signatures.signer(privateKeyMap, algorithm, charset, encoding);
    }

    public static EncodingSignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider, Charset charset, Encoding encoding) {
        return Signatures.signer(privateKeyMap, algorithm, provider, charset, encoding);
    }

    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, Encoding encoding) {
        return Signatures.signer(privateKey, algorithm, encoding);
    }

    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, Charset charset, Encoding encoding) {
        return Signatures.signer(privateKey, algorithm, charset, encoding);
    }

    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, String provider, Charset charset, Encoding encoding) {
        return Signatures.signer(privateKey, algorithm, provider, charset, encoding);
    }

    public static Verifier verifier(PublicKey publicKey, String algorithm) {
        return Signatures.verifier(publicKey, algorithm);
    }

    public static Verifier verifier(PublicKey publicKey, String algorithm, String provider) {
        return Signatures.verifier(publicKey, algorithm, provider);
    }

    public static VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm) {
        return Signatures.verifier(publicKeyMap, algorithm);
    }

    public static VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, String provider) {
        return Signatures.verifier(publicKeyMap, algorithm, provider);
    }

    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, Encoding encoding) {
        return Signatures.verifier(publicKey, algorithm, encoding);
    }

    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, String provider, Encoding encoding) {
        return Signatures.verifier(publicKey, algorithm, provider, encoding);
    }

    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, String provider, Charset charset, Encoding encoding) {
        return Signatures.verifier(publicKey, algorithm, provider, charset, encoding);
    }

    public static EncodingVerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, Encoding encoding) {
        return Signatures.verifier(publicKeyMap, algorithm, encoding);
    }

    public static EncodingVerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, Charset charset, Encoding encoding) {
        return Signatures.verifier(publicKeyMap, algorithm, charset, encoding);
    }

    public static EncodingVerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, String provider, Charset charset, Encoding encoding) {
        return Signatures.verifier(publicKeyMap, algorithm, provider, charset, encoding);
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

    public static CipherByKey cipher(String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return Ciphers.cipher(keyAlgorithm, cipherAlgorithm, mode);
    }

    public static CipherByKey cipher(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        return Ciphers.cipher(keyAlgorithm, cipherAlgorithm, provider, mode);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.Cipher cipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return Ciphers.cipher(key, keyAlgorithm, cipherAlgorithm, mode);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.Cipher cipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        return Ciphers.cipher(key, keyAlgorithm, cipherAlgorithm, provider, mode);
    }

    public static EncodingCipherByKey cipherByKey(String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset) {
        return Ciphers.cipherByKey(keyAlgorithm, cipherAlgorithm, mode, charset);
    }

    public static EncodingCipherByKey cipherByKey(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset) {
        return Ciphers.cipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode, charset);
    }

    public static EncodingCipher cipher(String key, String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset, Encoding encoding) {
        return Ciphers.cipher(key, keyAlgorithm, cipherAlgorithm, mode, charset, encoding);
    }

    public static EncodingCipher cipher(String key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset, Encoding encoding) {
        return Ciphers.cipher(key, keyAlgorithm, cipherAlgorithm, provider, mode, charset, encoding);
    }

    public static Cipher cipher(Key key, String algorithm, Mode mode) {
        return Ciphers.cipher(key, algorithm, mode);
    }

    public static Cipher cipher(Key key, String algorithm, String provider, Mode mode) {
        return Ciphers.cipher(key, algorithm, provider, mode);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey cipher(Map<String, Key> keys, String algorithm) {
        return Ciphers.cipher(keys, algorithm);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey cipher(Map<String, Key> keys, String algorithm, String provider) {
        return Ciphers.cipher(keys, algorithm, provider);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher cipher(Key key, String algorithm, Mode mode, Encoding encoding, Charset charset) {
        return Ciphers.cipher(key, algorithm, mode, encoding, charset);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher cipher(Key key, String algorithm, String provider, Mode mode, Encoding encoding, Charset charset) {
        return Ciphers.cipher(key, algorithm, provider, mode, encoding, charset);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey cipher(Map<String, Key> keys, String algorithm, Encoding encoding, Charset charset) {
        return Ciphers.cipher(keys, algorithm, encoding, charset);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey cipher(Map<String, Key> keys, String algorithm, String provider, Encoding encoding, Charset charset) {
        return Ciphers.cipher(keys, algorithm, provider, encoding, charset);
    }


    public enum Encoding {
        HEX,
        BASE64,
        URL,
        MIME
    }
}
