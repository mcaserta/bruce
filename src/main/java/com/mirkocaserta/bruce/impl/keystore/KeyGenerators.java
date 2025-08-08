package com.mirkocaserta.bruce.impl.keystore;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import javax.crypto.KeyGenerator;
import java.security.*;

/**
 * Implementation class for key generation operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class KeyGenerators {
    
    private KeyGenerators() {
        // utility class
    }
    
    /**
     * Generates a key pair using the default provider.
     *
     * @param algorithm the key algorithm (e.g., RSA)
     * @param keySize the key size in bits
     * @return the generated key pair
     */
    public static KeyPair generateKeyPair(String algorithm, int keySize) {
        return generateKeyPair(algorithm, null, keySize, null);
    }
    
    /**
     * Generates a key pair using a specific provider.
     *
     * @param algorithm the key algorithm
     * @param provider the JCA provider name
     * @param keySize the key size in bits
     * @return the generated key pair
     */
    public static KeyPair generateKeyPair(String algorithm, String provider, int keySize) {
        return generateKeyPair(algorithm, provider, keySize, null);
    }
    
    /**
     * Generates a key pair using a specific random source.
     *
     * @param algorithm the key algorithm
     * @param keySize the key size in bits
     * @param random the secure random source
     * @return the generated key pair
     */
    public static KeyPair generateKeyPair(String algorithm, int keySize, SecureRandom random) {
        return generateKeyPair(algorithm, null, keySize, random);
    }
    
    /**
     * Generates a key pair using a specific provider and random source.
     *
     * @param algorithm the key algorithm
     * @param provider the JCA provider name
     * @param keySize the key size in bits
     * @param random the secure random source
     * @return the generated key pair
     */
    public static KeyPair generateKeyPair(String algorithm, String provider, int keySize, SecureRandom random) {
        try {
            var keyGen = provider == null || provider.isBlank() ?
                    KeyPairGenerator.getInstance(algorithm) :
                    KeyPairGenerator.getInstance(algorithm, provider);

            if (random == null) {
                keyGen.initialize(keySize);
            } else {
                keyGen.initialize(keySize, random);
            }
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new BruceException(String.format("no such algorithm: %s", algorithm), e);
        } catch (InvalidParameterException e) {
            throw new BruceException(String.format("invalid key size: %d", keySize), e);
        } catch (NoSuchProviderException e) {
            throw new BruceException(String.format("no such provider: %s", provider), e);
        }
    }
    
    /**
     * Generates a random symmetric key and returns the raw bytes.
     *
     * @param algorithm the key algorithm (e.g., AES)
     * @return the generated key bytes
     */
    public static byte[] generateSymmetricKey(String algorithm) {
        return generateSymmetricKey(algorithm, "");
    }
    
    /**
     * Generates a random symmetric key using a specific provider and returns the raw bytes.
     *
     * @param algorithm the key algorithm
     * @param provider the JCA provider name
     * @return the generated key bytes
     */
    public static byte[] generateSymmetricKey(String algorithm, String provider) {
        try {
            var generator = provider == null || provider.isBlank()
                    ? KeyGenerator.getInstance(algorithm)
                    : KeyGenerator.getInstance(algorithm, provider);
            generator.init(new SecureRandom());
            return generator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new BruceException(String.format("cannot generate key: algorithm=%s, provider=%s", algorithm, provider), e);
        }
    }
    
    /**
     * Generates a random symmetric key and returns it encoded.
     *
     * @param algorithm the key algorithm
     * @param encoding the output encoding
     * @return the encoded key
     */
    public static String generateEncodedSymmetricKey(String algorithm, Bruce.Encoding encoding) {
        return generateEncodedSymmetricKey(algorithm, "", encoding);
    }
    
    /**
     * Generates a random symmetric key using a specific provider and returns it encoded.
     *
     * @param algorithm the key algorithm
     * @param provider the JCA provider name
     * @param encoding the output encoding
     * @return the encoded key
     */
    public static String generateEncodedSymmetricKey(String algorithm, String provider, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, generateSymmetricKey(algorithm, provider));
    }
}