package com.mirkocaserta.bruce.impl.mac;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;
import com.mirkocaserta.bruce.mac.EncodingMac;
import com.mirkocaserta.bruce.mac.Mac;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Implementation class for MAC (Message Authentication Code) operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class MacOperations {
    
    private static final String BLANK = "";
    
    private MacOperations() {
        // utility class
    }
    
    /**
     * Creates a MAC calculator using the default provider.
     *
     * @param key the secret key
     * @param algorithm the MAC algorithm (e.g., HmacSHA256)
     * @return a MAC interface producing raw bytes
     */
    public static Mac createMac(Key key, String algorithm) {
        return createMac(key, algorithm, BLANK);
    }
    
    /**
     * Creates a MAC calculator using a specific provider.
     *
     * @param key the secret key
     * @param algorithm the MAC algorithm
     * @param provider the JCA provider name
     * @return a MAC interface producing raw bytes
     */
    public static Mac createMac(Key key, String algorithm, String provider) {
        return message -> {
            try {
                var mac = provider == null || provider.isBlank()
                        ? javax.crypto.Mac.getInstance(algorithm)
                        : javax.crypto.Mac.getInstance(algorithm, provider);
                mac.init(key);
                return mac.doFinal(message);
            } catch (NoSuchAlgorithmException e) {
                throw new BruceException(String.format("no such algorithm: %s", key.getAlgorithm()), e);
            } catch (InvalidKeyException e) {
                throw new BruceException("invalid key", e);
            } catch (NoSuchProviderException e) {
                throw new BruceException(String.format("no such provider: %s", provider), e);
            }
        };
    }
    
    /**
     * Creates an encoding MAC calculator using the default provider.
     *
     * @param key the secret key
     * @param algorithm the MAC algorithm
     * @param encoding the output encoding
     * @param charset the input charset
     * @return an encoding MAC interface
     */
    public static EncodingMac createEncodingMac(Key key, String algorithm, Bruce.Encoding encoding, Charset charset) {
        return createEncodingMac(key, algorithm, BLANK, encoding, charset);
    }
    
    /**
     * Creates an encoding MAC calculator using a specific provider.
     *
     * @param key the secret key
     * @param algorithm the MAC algorithm
     * @param provider the JCA provider name
     * @param encoding the output encoding
     * @param charset the input charset
     * @return an encoding MAC interface
     */
    public static EncodingMac createEncodingMac(Key key, String algorithm, String provider, Bruce.Encoding encoding, Charset charset) {
        var mac = createMac(key, algorithm, provider);
        return message -> EncodingUtils.encode(encoding, mac.get(message.getBytes(charset)));
    }
}