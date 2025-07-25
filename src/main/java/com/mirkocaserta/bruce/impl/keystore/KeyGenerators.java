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
    
    public static KeyPair generateKeyPair(String algorithm, int keySize) {
        return generateKeyPair(algorithm, null, keySize, null);
    }
    
    public static KeyPair generateKeyPair(String algorithm, String provider, int keySize) {
        return generateKeyPair(algorithm, provider, keySize, null);
    }
    
    public static KeyPair generateKeyPair(String algorithm, int keySize, SecureRandom random) {
        return generateKeyPair(algorithm, null, keySize, random);
    }
    
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
    
    public static byte[] generateSymmetricKey(String algorithm) {
        return generateSymmetricKey(algorithm, "");
    }
    
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
    
    public static String generateEncodedSymmetricKey(String algorithm, Bruce.Encoding encoding) {
        return generateEncodedSymmetricKey(algorithm, "", encoding);
    }
    
    public static String generateEncodedSymmetricKey(String algorithm, String provider, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, generateSymmetricKey(algorithm, provider));
    }
}