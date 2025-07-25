package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.Mode;
import com.mirkocaserta.bruce.cipher.asymmetric.Cipher;
import com.mirkocaserta.bruce.cipher.symmetric.CipherByKey;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipher;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipherByKey;
import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.digest.EncodingDigester;
import com.mirkocaserta.bruce.digest.FileDigester;
import com.mirkocaserta.bruce.impl.cipher.AsymmetricCipherOperations;
import com.mirkocaserta.bruce.impl.cipher.SymmetricCipherOperations;
import com.mirkocaserta.bruce.impl.digest.DigestOperations;
import com.mirkocaserta.bruce.impl.keystore.KeyGenerators;
import com.mirkocaserta.bruce.impl.keystore.KeyStoreOperations;
import com.mirkocaserta.bruce.impl.mac.MacOperations;
import com.mirkocaserta.bruce.impl.signature.SignatureOperations;
import com.mirkocaserta.bruce.mac.EncodingMac;
import com.mirkocaserta.bruce.mac.Mac;
import com.mirkocaserta.bruce.signature.Signer;
import com.mirkocaserta.bruce.signature.*;

import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * <p>This class is the main entrypoint for all cryptographic operations.</p>
 *
 * <p>Just type <code>Bruce.</code> in your IDE and let autocompletion do
 * the rest.</p>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class Bruce {

    /**
     * The default keystore format/type.
     */
    public static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

    private Bruce() {
        // utility class, users can't make new instances
    }

    // Builder Pattern Factory Methods

    /**
     * Creates a new cipher builder for fluent cipher configuration.
     * 
     * @return a new cipher builder
     */
    public static CipherBuilder cipherBuilder() {
        return new CipherBuilder();
    }

    /**
     * Creates a new signer builder for fluent signer configuration.
     * 
     * @return a new signer builder
     */
    public static SignerBuilder signerBuilder() {
        return new SignerBuilder();
    }

    /**
     * Creates a new verifier builder for fluent verifier configuration.
     * 
     * @return a new verifier builder
     */
    public static VerifierBuilder verifierBuilder() {
        return new VerifierBuilder();
    }

    /**
     * Creates a new digest builder for fluent digest configuration.
     * 
     * @return a new digest builder
     */
    public static DigestBuilder digestBuilder() {
        return new DigestBuilder();
    }

    /**
     * Creates a new MAC builder for fluent MAC configuration.
     * 
     * @return a new MAC builder
     */
    public static MacBuilder macBuilder() {
        return new MacBuilder();
    }

    /**
     * Returns the default keystore using configuration from the following
     * system properties:
     *
     * <ul>
     *   <li><code>javax.net.ssl.keyStore</code></li>
     *   <li><code>javax.net.ssl.keyStorePassword</code></li>
     * </ul>
     * <p>
     * The keystore location supports the following protocols:
     *
     * <ul>
     *   <li><code>classpath:</code></li>
     *   <li><code>http:</code></li>
     *   <li><code>https:</code></li>
     *   <li><code>file:</code></li>
     * </ul>
     * <p>
     * If no protocol is specified, <code>file</code> is assumed.
     * <p>
     * The default keystore type is {@value #DEFAULT_KEYSTORE_TYPE}.
     *
     * @return the default keystore
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore() {
        return KeyStoreOperations.loadDefaultKeyStore();
    }

    /**
     * Returns the default keystore using configuration from the following
     * system properties:
     *
     * <ul>
     *   <li><code>javax.net.ssl.keyStore</code></li>
     *   <li><code>javax.net.ssl.keyStorePassword</code></li>
     * </ul>
     * <p>
     * The keystore location supports the following protocols:
     *
     * <ul>
     *   <li><code>classpath:</code></li>
     *   <li><code>http:</code></li>
     *   <li><code>https:</code></li>
     *   <li><code>file:</code></li>
     * </ul>
     * <p>
     * If no protocol is specified, <code>file</code> is assumed.
     *
     * @param type the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
     * @return the default keystore
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore(String type) {
        return KeyStoreOperations.loadKeyStore(type);
    }

    /**
     * Returns a key store. The default keystore type is {@value #DEFAULT_KEYSTORE_TYPE}.
     *
     * @param location the keystore location. The following protocols are supported:
     *                 <ul>
     *                 <li><code>classpath:</code></li>
     *                 <li><code>http:</code></li>
     *                 <li><code>https:</code></li>
     *                 <li><code>file:</code></li>
     *                 </ul>
     *                 If no protocol is specified, <code>file</code> is assumed.
     * @param password the password
     * @return a key store
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore(String location, char[] password) {
        return KeyStoreOperations.loadKeyStore(location, password);
    }

    /**
     * Returns a key store. The default keystore type is {@value #DEFAULT_KEYSTORE_TYPE}.
     * Convenience overload that accepts String password for easier usage.
     *
     * @param location the keystore location. The following protocols are supported:
     *                 <ul>
     *                 <li><code>classpath:</code></li>
     *                 <li><code>http:</code></li>
     *                 <li><code>https:</code></li>
     *                 <li><code>file:</code></li>
     *                 </ul>
     *                 If no protocol is specified, <code>file</code> is assumed.
     * @param password the password
     * @return a key store
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore(String location, String password) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray());
    }

    /**
     * Returns a key store.
     *
     * @param location the keystore location. The following protocols are supported:
     *                 <ul>
     *                 <li><code>classpath:</code></li>
     *                 <li><code>http:</code></li>
     *                 <li><code>https:</code></li>
     *                 <li><code>file:</code></li>
     *                 </ul>
     *                 If no protocol is specified, <code>file</code> is assumed.
     * @param password the password
     * @param type     the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
     * @return a key store
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore(String location, char[] password, String type) {
        return KeyStoreOperations.loadKeyStore(location, password, type);
    }

    /**
     * Returns a key store.
     * Convenience overload that accepts String password for easier usage.
     *
     * @param location the keystore location. The following protocols are supported:
     *                 <ul>
     *                 <li><code>classpath:</code></li>
     *                 <li><code>http:</code></li>
     *                 <li><code>https:</code></li>
     *                 <li><code>file:</code></li>
     *                 </ul>
     *                 If no protocol is specified, <code>file</code> is assumed.
     * @param password the password
     * @param type     the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
     * @return a key store
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore(String location, String password, String type) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray(), type);
    }

    /**
     * Returns a key store.
     *
     * @param location the keystore location. The following protocols are supported:
     *                 <ul>
     *                 <li><code>classpath:</code></li>
     *                 <li><code>http:</code></li>
     *                 <li><code>https:</code></li>
     *                 <li><code>file:</code></li>
     *                 </ul>
     *                 If no protocol is specified, <code>file</code> is assumed.
     * @param password the password
     * @param type     the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
     * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return a key store
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore(String location, char[] password, String type, String provider) {
        return KeyStoreOperations.loadKeyStore(location, password, type, provider);
    }

    /**
     * Loads a key store from the given location using the specified password, type and provider.
     *
     * @param location the keystore location. The following protocols are supported:
     *                 <ul>
     *                 <li><code>classpath:</code></li>
     *                 <li><code>http:</code></li>
     *                 <li><code>https:</code></li>
     *                 <li><code>file:</code></li>
     *                 </ul>
     *                 If no protocol is specified, <code>file</code> is assumed.
     * @param password the password
     * @param type     the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
     * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return a key store
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore(String location, String password, String type, String provider) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray(), type, provider);
    }

    /**
     * Loads a certificate from the given keystore.
     *
     * @param keystore the keystore to read from
     * @param alias    the certificate alias
     * @return the certificate
     * @throws BruceException on loading errors
     */
    public static Certificate certificate(KeyStore keystore, String alias) {
        return KeyStoreOperations.loadCertificate(keystore, alias);
    }

    /**
     * Loads a public key from the given keystore.
     *
     * @param keystore the keystore to read from
     * @param alias    the certificate alias
     * @return the public key
     * @throws BruceException on loading errors
     */
    public static PublicKey publicKey(KeyStore keystore, String alias) {
        return KeyStoreOperations.extractPublicKey(keystore, alias);
    }

    /**
     * Loads a private key from the given keystore.
     *
     * @param keystore the keystore to read from
     * @param alias    the certificate alias
     * @param password the private key password
     * @return the private key
     * @throws BruceException on loading errors
     */
    public static PrivateKey privateKey(KeyStore keystore, String alias, String password) {
        return KeyStoreOperations.loadPrivateKey(keystore, alias, password.toCharArray());
    }

    /**
     * Loads a private key from the given keystore.
     *
     * @param keystore the keystore to read from
     * @param alias    the certificate alias
     * @param password the private key password
     * @return the private key
     * @throws BruceException on loading errors
     */
    public static PrivateKey privateKey(KeyStore keystore, String alias, char[] password) {
        return KeyStoreOperations.loadPrivateKey(keystore, alias, password);
    }

    /**
     * Loads a secret key from the given keystore.
     *
     * @param keystore the keystore to read from
     * @param alias    the secret key alias
     * @param password the secret key password
     * @return the secret key
     * @throws BruceException on loading errors
     */
    public static Key secretKey(KeyStore keystore, String alias, String password) {
        return KeyStoreOperations.loadSecretKey(keystore, alias, password.toCharArray());
    }

    /**
     * Loads a secret key from the given keystore.
     *
     * @param keystore the keystore to read from
     * @param alias    the secret key alias
     * @param password the secret key password
     * @return the secret key
     * @throws BruceException on loading errors
     */
    public static Key secretKey(KeyStore keystore, String alias, char[] password) {
        return KeyStoreOperations.loadSecretKey(keystore, alias, password);
    }

    /**
     * Generates a key pair.
     *
     * @param algorithm the key algorithm
     * @param keySize   the key size
     * @return the key pair
     */
    public static KeyPair keyPair(String algorithm, int keySize) {
        return KeyGenerators.generateKeyPair(algorithm, keySize);
    }

    /**
     * Generates a key pair.
     *
     * @param algorithm the key algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param keySize   the key size
     * @return the key pair
     */
    public static KeyPair keyPair(String algorithm, String provider, int keySize) {
        return KeyGenerators.generateKeyPair(algorithm, provider, keySize);
    }

    /**
     * Generates a key pair with the specified random number generator.
     *
     * @param algorithm the key algorithm
     * @param keySize   the key size
     * @param random    the random number generator
     * @return the key pair
     */
    public static KeyPair keyPair(String algorithm, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithm, keySize, random);
    }

    /**
     * Generates a key pair with the specified provider and random number generator.
     *
     * @param algorithm the key algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param keySize   the key size
     * @param random    the random number generator
     * @return the key pair
     */
    public static KeyPair keyPair(String algorithm, String provider, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithm, provider, keySize, random);
    }

    /**
     * Returns an encoding message digester for the given algorithm.
     * <p>
     * This digester implementation assumes your input messages
     * are using the <code>UTF-8</code> charset.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param encoding  the encoding
     * @return an encoding message digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingDigester digester(String algorithm, Encoding encoding) {
        return DigestOperations.createEncodingDigester(algorithm, encoding);
    }

    /**
     * Returns an encoding message digester for the given algorithm and character set.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param encoding  the encoding
     * @param charset   the charset used for the input messages
     * @return an encoding message digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingDigester digester(String algorithm, Encoding encoding, Charset charset) {
        return DigestOperations.createEncodingDigester(algorithm, encoding, charset);
    }

    /**
     * Returns an encoding message digester for the given algorithm and provider.
     * <p>
     * This digester implementation assumes your input messages
     * are using the <code>UTF-8</code> charset.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the encoding
     * @return an encoding message digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingDigester digester(String algorithm, String provider, Encoding encoding) {
        return DigestOperations.createEncodingDigester(algorithm, provider, encoding);
    }

    /**
     * Returns an encoding message digester for the given algorithm and provider.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the encoding
     * @param charset   the charset used for the input messages
     * @return an encoding message digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingDigester digester(String algorithm, String provider, Encoding encoding, Charset charset) {
        return DigestOperations.createEncodingDigester(algorithm, provider, encoding, charset);
    }

    /**
     * Returns an encoding file digester for the given algorithm.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param encoding  the encoding
     * @return an encoding file digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static FileDigester fileDigester(String algorithm, Encoding encoding) {
        return DigestOperations.createFileDigester(algorithm, encoding);
    }

    /**
     * Returns an encoding file digester for the given algorithm and provider.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the encoding
     * @return an encoding file digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static FileDigester fileDigester(String algorithm, String provider, Encoding encoding) {
        return DigestOperations.createFileDigester(algorithm, provider, encoding);
    }

    /**
     * Returns a raw byte array message digester for the given algorithm and provider.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return a raw byte array message digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static Digester digester(String algorithm, String provider) {
        return DigestOperations.createRawDigester(algorithm, provider);
    }

    /**
     * Returns a raw byte array message digester for the given algorithm.
     *
     * @param algorithm the algorithm (ex: SHA1, MD5, etc)
     * @return a raw byte array message digester
     * @throws BruceException on no such algorithm exception
     */
    public static Digester digester(String algorithm) {
        return DigestOperations.createRawDigester(algorithm);
    }

    /**
     * Returns a signer for the given private key and
     * algorithm.
     *
     * @param privateKey the signing key
     * @param algorithm  the signing algorithm
     * @return the signer
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static Signer signer(PrivateKey privateKey, String algorithm) {
        return SignatureOperations.createSigner(privateKey, algorithm);
    }

    /**
     * Returns a signer for the given private key,
     * algorithm and provider.
     *
     * @param privateKey the signing key
     * @param algorithm  the signing algorithm
     * @param provider   the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return the signer
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static Signer signer(PrivateKey privateKey, String algorithm, String provider) {
        return SignatureOperations.createSigner(privateKey, algorithm, provider);
    }

    /**
     * Returns a signer where the private key can be chosen at runtime.
     * The signing keys must be provided in a map where the map key is an
     * alias to the signing key and the value is the corresponding signing key.
     *
     * @param privateKeyMap the signing key map
     * @param algorithm     the signing algorithm
     * @return the signer
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm) {
        return SignatureOperations.createSignerByKey(privateKeyMap, algorithm);
    }

    /**
     * Returns a signer where the private key can be chosen at runtime.
     * The signing keys must be provided in a map where the map key is an
     * alias to the signing key and the value is the corresponding signing key.
     *
     * @param privateKeyMap the signing key map
     * @param algorithm     the signing algorithm
     * @param provider      the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return the signer
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider) {
        return SignatureOperations.createSignerByKey(privateKeyMap, algorithm, provider);
    }

    /**
     * Returns an encoding signer where the private key can be chosen at runtime.
     * The signing keys must be provided in a map where the map key is an
     * alias to the signing key and the value is the corresponding signing key.
     * <p>
     * The implementation assumes your input messages use the <code>UTF-8</code> charset.
     *
     * @param privateKeyMap the signing key map
     * @param algorithm     the signing algorithm
     * @param encoding      the signature encoding
     * @return the signer
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingSignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, Encoding encoding) {
        return SignatureOperations.createEncodingSignerByKey(privateKeyMap, algorithm, encoding);
    }

    /**
     * Returns an encoding signer where the private key can be chosen at runtime.
     * The signing keys must be provided in a map where the map key is an
     * alias to the signing key and the value is the corresponding signing key.
     *
     * @param privateKeyMap the signing key map
     * @param algorithm     the signing algorithm
     * @param charset       the charset used in messages
     * @param encoding      the signature encoding
     * @return the signer
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingSignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, Charset charset, Encoding encoding) {
        return SignatureOperations.createEncodingSignerByKey(privateKeyMap, algorithm, charset, encoding);
    }

    /**
     * Returns an encoding signer where the private key can be chosen at runtime.
     * The signing keys must be provided in a map where the map key is an
     * alias to the signing key and the value is the corresponding signing key.
     *
     * @param privateKeyMap the signing key map
     * @param algorithm     the signing algorithm
     * @param provider      the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param charset       the charset used in messages
     * @param encoding      the signature encoding
     * @return the signer
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingSignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider, Charset charset, Encoding encoding) {
        return SignatureOperations.createEncodingSignerByKey(privateKeyMap, algorithm, provider, charset, encoding);
    }

    /**
     * Returns an encoding signer for the given private key using the
     * default provider and {@link java.nio.charset.StandardCharsets#UTF_8}
     * as the default charset used in messages.
     *
     * @param privateKey the signing key
     * @param algorithm  the signing algorithm
     * @param encoding   the signature encoding
     * @return the signer
     * @throws BruceException on initialization exceptions
     */
    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, Encoding encoding) {
        return SignatureOperations.createEncodingSigner(privateKey, algorithm, encoding);
    }

    /**
     * Returns an encoding signer for the given private key using the
     * default provider.
     *
     * @param privateKey the signing key
     * @param algorithm  the signing algorithm
     * @param charset    the charset used in messages
     * @param encoding   the signature encoding
     * @return the signer
     * @throws BruceException on initialization exceptions
     */
    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, Charset charset, Encoding encoding) {
        return SignatureOperations.createEncodingSigner(privateKey, algorithm, charset, encoding);
    }

    /**
     * Returns an encoding signer for the given private key.
     *
     * @param privateKey the signing key
     * @param algorithm  the signing algorithm
     * @param provider   the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param charset    the charset used in messages
     * @param encoding   the signature encoding
     * @return the signer
     * @throws BruceException on initialization exceptions
     */
    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, String provider, Charset charset, Encoding encoding) {
        return SignatureOperations.createEncodingSigner(privateKey, algorithm, provider, charset, encoding);
    }

    /**
     * Returns a verifier for the given public key and
     * algorithm using the default provider.
     *
     * @param publicKey the verification key
     * @param algorithm the verification algorithm
     * @return the verifier
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static Verifier verifier(PublicKey publicKey, String algorithm) {
        return SignatureOperations.createVerifier(publicKey, algorithm);
    }

    /**
     * Returns a verifier for the given public key,
     * algorithm and provider.
     *
     * @param publicKey the verification key
     * @param algorithm the verification algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return the verifier
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static Verifier verifier(PublicKey publicKey, String algorithm, String provider) {
        return SignatureOperations.createVerifier(publicKey, algorithm, provider);
    }

    /**
     * Returns a verifier where the public key can be chosen at runtime.
     * The verification keys must be provided in a map where the map key is an
     * alias to the verification key and the value is the corresponding
     * verification key. This method uses the default provider.
     *
     * @param publicKeyMap the verification key map
     * @param algorithm    the verification algorithm
     * @return the verifier
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm) {
        return SignatureOperations.createVerifierByKey(publicKeyMap, algorithm);
    }

    /**
     * Returns a verifier where the public key can be chosen at runtime.
     * The verification keys must be provided in a map where the map key is an
     * alias to the verification key and the value is the corresponding
     * verification key.
     *
     * @param publicKeyMap the verification key map
     * @param algorithm    the verification algorithm
     * @param provider     the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return the verifier
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, String provider) {
        return SignatureOperations.createVerifierByKey(publicKeyMap, algorithm, provider);
    }

    /**
     * Returns an encoding verifier for the given public key.
     * This method assumes the default messages charset is
     * {@link java.nio.charset.StandardCharsets#UTF_8}. The default provider
     * is used.
     *
     * @param publicKey the verification key
     * @param algorithm the verification algorithm
     * @param encoding  the verification encoding
     * @return the verifier
     * @throws BruceException on initialization exceptions
     */
    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, Encoding encoding) {
        return SignatureOperations.createEncodingVerifier(publicKey, algorithm, encoding);
    }

    /**
     * Returns an encoding verifier for the given public key.
     * This method assumes the default messages charset is
     * {@link java.nio.charset.StandardCharsets#UTF_8}.
     *
     * @param publicKey the verification key
     * @param algorithm the verification algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the verification encoding
     * @return the verifier
     * @throws BruceException on initialization exceptions
     */
    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, String provider, Encoding encoding) {
        return SignatureOperations.createEncodingVerifier(publicKey, algorithm, provider, encoding);
    }

    /**
     * Returns an encoding verifier for the given public key.
     *
     * @param publicKey the verification key
     * @param algorithm the verification algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param charset   the charset used in messages
     * @param encoding  the verification encoding
     * @return the verifier
     * @throws BruceException on initialization exceptions
     */
    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, String provider, Charset charset, Encoding encoding) {
        return SignatureOperations.createEncodingVerifier(publicKey, algorithm, provider, charset, encoding);
    }

    /**
     * Returns an encoding verifier where the public key can be chosen at runtime.
     * The verification keys must be provided in a map where the map key is an
     * alias to the verification key and the value is the corresponding
     * verification key.
     * <p>
     * The implementation assumes your input messages use the <code>UTF-8</code> charset.
     *
     * @param publicKeyMap the verification key map
     * @param algorithm    the verification algorithm
     * @param encoding     the verification encoding
     * @return the verifier
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingVerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, Encoding encoding) {
        return SignatureOperations.createEncodingVerifierByKey(publicKeyMap, algorithm, encoding);
    }

    /**
     * Returns an encoding verifier where the public key can be chosen at runtime.
     * The verification keys must be provided in a map where the map key is an
     * alias to the verification key and the value is the corresponding
     * verification key.
     *
     * @param publicKeyMap the verification key map
     * @param algorithm    the verification algorithm
     * @param charset      the charset used in messages
     * @param encoding     the verification encoding
     * @return the verifier
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingVerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, Charset charset, Encoding encoding) {
        return SignatureOperations.createEncodingVerifierByKey(publicKeyMap, algorithm, charset, encoding);
    }

    /**
     * Returns an encoding verifier where the public key can be chosen at runtime.
     * The verification keys must be provided in a map where the map key is an
     * alias to the verification key and the value is the corresponding
     * verification key.
     *
     * @param publicKeyMap the verification key map
     * @param algorithm    the verification algorithm
     * @param provider     the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param charset      the charset used in messages
     * @param encoding     the verification encoding
     * @return the verifier
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingVerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, String provider, Charset charset, Encoding encoding) {
        return SignatureOperations.createEncodingVerifierByKey(publicKeyMap, algorithm, provider, charset, encoding);
    }

    /**
     * Generates a symmetric key using the specified algorithm.
     *
     * @param algorithm the key algorithm
     * @return a newly generated symmetric key
     */
    public static byte[] symmetricKey(String algorithm) {
        return KeyGenerators.generateSymmetricKey(algorithm);
    }

    /**
     * Generates a symmetric key using the specified algorithm
     * and provider.
     *
     * @param algorithm the key algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return a newly generated symmetric key
     */
    public static byte[] symmetricKey(String algorithm, String provider) {
        return KeyGenerators.generateSymmetricKey(algorithm, provider);
    }

    /**
     * Generates an encoded symmetric key using the specified algorithm.
     *
     * @param algorithm the key algorithm
     * @param encoding  the key encoding
     * @return a newly generated symmetric key
     */
    public static String symmetricKey(String algorithm, Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithm, encoding);
    }

    /**
     * Generates an encoded symmetric key using the specified algorithm
     * and provider.
     *
     * @param algorithm the key algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the key encoding
     * @return a newly generated symmetric key
     */
    public static String symmetricKey(String algorithm, String provider, Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithm, provider, encoding);
    }

    /**
     * Returns a symmetric cipher where the key is selectable at runtime
     * through the returned interface.
     *
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param mode            the encryption mode
     * @return the symmetric cipher
     */
    public static CipherByKey cipher(String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return SymmetricCipherOperations.createCipherByKey(keyAlgorithm, cipherAlgorithm, mode);
    }

    /**
     * Returns a symmetric cipher where the key is selectable at runtime
     * through the returned interface.
     *
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param provider        the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode            the encryption mode
     * @return the symmetric cipher
     */
    public static CipherByKey cipher(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        return SymmetricCipherOperations.createCipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode);
    }

    /**
     * Returns a symmetric cipher.
     *
     * @param key             the ciphering key
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param mode            the encryption mode
     * @return the symmetric cipher
     */
    public static com.mirkocaserta.bruce.cipher.symmetric.Cipher cipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return SymmetricCipherOperations.createCipher(key, keyAlgorithm, cipherAlgorithm, mode);
    }

    /**
     * Returns a symmetric cipher.
     *
     * @param key             the ciphering key
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param provider        the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode            the encryption mode
     * @return the symmetric cipher
     */
    public static com.mirkocaserta.bruce.cipher.symmetric.Cipher cipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        return SymmetricCipherOperations.createCipher(key, keyAlgorithm, cipherAlgorithm, provider, mode);
    }

    /**
     * Returns a symmetric cipher where the key is selectable at runtime
     * through the returned interface.
     *
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param mode            the encryption mode
     * @param charset         the message charset
     * @return the symmetric cipher
     */
    public static EncodingCipherByKey cipherByKey(String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset) {
        return SymmetricCipherOperations.createEncodingCipherByKey(keyAlgorithm, cipherAlgorithm, mode, charset);
    }

    /**
     * Returns a symmetric cipher where the key is selectable at runtime
     * through the returned interface.
     *
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param provider        the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode            the encryption mode
     * @param charset         the message charset
     * @return the symmetric cipher
     */
    public static EncodingCipherByKey cipherByKey(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset) {
        return SymmetricCipherOperations.createEncodingCipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode, charset);
    }

    /**
     * Returns a symmetric cipher.
     *
     * @param key             the encryption/decryption key
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param mode            the encryption mode
     * @param charset         the message charset
     * @param encoding        the message encoding
     * @return the symmetric cipher
     */
    public static EncodingCipher cipher(String key, String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset, Encoding encoding) {
        return SymmetricCipherOperations.createEncodingCipher(key, keyAlgorithm, cipherAlgorithm, mode, charset, encoding);
    }

    /**
     * Returns a symmetric cipher.
     *
     * @param key             the encryption/decryption key
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param provider        the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode            the encryption mode
     * @param charset         the message charset
     * @param encoding        the message encoding
     * @return the symmetric cipher
     */
    public static EncodingCipher cipher(String key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset, Encoding encoding) {
        return SymmetricCipherOperations.createEncodingCipher(key, keyAlgorithm, cipherAlgorithm, provider, mode, charset, encoding);
    }

    /**
     * Returns an asymmetric cipher.
     *
     * @param key       the ciphering key
     * @param algorithm the algorithm
     * @param mode      the encryption mode
     * @return the asymmetric cipher
     */
    public static Cipher cipher(Key key, String algorithm, Mode mode) {
        return AsymmetricCipherOperations.createCipher(key, algorithm, mode);
    }

    /**
     * Returns an asymmetric cipher.
     *
     * @param key       the ciphering key
     * @param algorithm the algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode      the encryption mode
     * @return the asymmetric cipher
     */
    public static Cipher cipher(Key key, String algorithm, String provider, Mode mode) {
        return AsymmetricCipherOperations.createCipher(key, algorithm, provider, mode);
    }

    /**
     * Returns an asymmetric cipher with a map of preconfigured keys.
     *
     * @param keys      a map of keys where the key is the key id and the value is the key
     * @param algorithm the algorithm
     * @return an asymmetric cipher with a map of preconfigured keys
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey cipher(Map<String, Key> keys, String algorithm) {
        return AsymmetricCipherOperations.createCipherByKey(keys, algorithm);
    }

    /**
     * Returns an asymmetric cipher with a map of preconfigured keys.
     *
     * @param keys      a map of keys where the key is the key id and the value is the key
     * @param algorithm the algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return an asymmetric cipher with a map of preconfigured keys
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey cipher(Map<String, Key> keys, String algorithm, String provider) {
        return AsymmetricCipherOperations.createCipherByKey(keys, algorithm, provider);
    }

    /**
     * Returns an encoding asymmetric cipher.
     *
     * @param key       the cipher's key
     * @param algorithm the algorithm
     * @param mode      the cipher mode: encrypt/decrypt
     * @param encoding  the message encoding
     * @param charset   the message charset
     * @return an encoding asymmetric cipher
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher cipher(Key key, String algorithm, Mode mode, Encoding encoding, Charset charset) {
        return AsymmetricCipherOperations.createEncodingCipher(key, algorithm, mode, encoding, charset);
    }

    /**
     * Returns an encoding asymmetric cipher.
     *
     * @param key       the cipher's key
     * @param algorithm the algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode      the cipher mode: encrypt/decrypt
     * @param encoding  the message encoding
     * @param charset   the message charset
     * @return an encoding asymmetric cipher
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher cipher(Key key, String algorithm, String provider, Mode mode, Encoding encoding, Charset charset) {
        return AsymmetricCipherOperations.createEncodingCipher(key, algorithm, provider, mode, encoding, charset);
    }

    /**
     * Returns an encoding asymmetric cipher with a map of preconfigured keys.
     *
     * @param keys      a map of keys where the key is the key id and the value is the key
     * @param algorithm the algorithm
     * @param encoding  the message encoding
     * @param charset   the message charset
     * @return an encoding asymmetric cipher with a map of preconfigured keys
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey cipher(Map<String, Key> keys, String algorithm, Encoding encoding, Charset charset) {
        return AsymmetricCipherOperations.createEncodingCipherByKey(keys, algorithm, encoding, charset);
    }

    /**
     * Returns an encoding asymmetric cipher with a map of preconfigured keys.
     *
     * @param keys      a map of keys where the key is the key id and the value is the key
     * @param algorithm the algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the message encoding
     * @param charset   the message charset
     * @return an encoding asymmetric cipher with a map of preconfigured keys
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey cipher(Map<String, Key> keys, String algorithm, String provider, Encoding encoding, Charset charset) {
        return AsymmetricCipherOperations.createEncodingCipherByKey(keys, algorithm, provider, encoding, charset);
    }

    /**
     * Returns an interface for producing message authentication codes.
     *
     * @param key       the secret key for digesting the messages
     * @param algorithm the signature algorithm
     * @return the message authentication codes interface
     */
    public static Mac mac(Key key, String algorithm) {
        return MacOperations.createMac(key, algorithm);
    }

    /**
     * Returns an interface for producing message authentication codes.
     *
     * @param key       the secret key for digesting the messages
     * @param algorithm the signature algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return the message authentication codes interface
     */
    public static Mac mac(Key key, String algorithm, String provider) {
        return MacOperations.createMac(key, algorithm, provider);
    }

    /**
     * Returns an interface for producing encoded message authentication codes.
     *
     * @param key       the secret key for digesting the messages
     * @param algorithm the signature algorithm
     * @param encoding  the signature encoding
     * @param charset   the message charset
     * @return the message authentication codes interface
     */
    public static EncodingMac mac(Key key, String algorithm, Encoding encoding, Charset charset) {
        return MacOperations.createEncodingMac(key, algorithm, encoding, charset);
    }

    /**
     * Returns an interface for producing encoded message authentication codes.
     *
     * @param key       the secret key for digesting the messages
     * @param algorithm the signature algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the signature encoding
     * @param charset   the message charset
     * @return the message authentication codes interface
     */
    public static EncodingMac mac(Key key, String algorithm, String provider, Encoding encoding, Charset charset) {
        return MacOperations.createEncodingMac(key, algorithm, provider, encoding, charset);
    }

    /**
     * Bruce supports these encodings. Encodings are used
     * in cryptography as a wire safe representation of raw
     * bytes which would otherwise get screwed-up in all
     * sort of possible ways while traversing networks or,
     * more generally, while exchanging hands.
     * <p>
     * Have you ever played the
     * <a href="https://en.wikipedia.org/wiki/Chinese_whispers">telephone game</a>?
     * Computers do that with raw bytes as different architectures
     * internally encode bytes in different ways. Unless you
     * use a standard encoding, messages get lost in translation
     * with catastrophic consequences.
     */
    public enum Encoding {
        /**
         * Hexadecimal encoding. For instance, the hexadecimal
         * encoding of a random MD5 hash is
         * <code>78e731027d8fd50ed642340b7c9a63b3</code>.
         */
        HEX,
        /**
         * Base64 encoding. For instance, the Base64 encoding of
         * a random MD5 hash is <code>eOcxAn2P1Q7WQjQLfJpjsw==</code>.
         */
        BASE64,
        /**
         * URL encoding. For instance, the URL encoding of a random
         * MD5 hash is <code>eOcxAn2P1Q7WQjQLfJpjsw==</code>.
         */
        URL,
        /**
         * MIME encoding. For instance, the MIME encoding of a random
         * MD5 hash is <code>eOcxAn2P1Q7WQjQLfJpjsw==</code>.
         */
        MIME
    }

}