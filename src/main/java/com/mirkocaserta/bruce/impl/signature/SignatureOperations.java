package com.mirkocaserta.bruce.impl.signature;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;
import com.mirkocaserta.bruce.signature.EncodingSigner;
import com.mirkocaserta.bruce.signature.EncodingSignerByKey;
import com.mirkocaserta.bruce.signature.EncodingVerifier;
import com.mirkocaserta.bruce.signature.EncodingVerifierByKey;
import com.mirkocaserta.bruce.signature.SignerByKey;
import com.mirkocaserta.bruce.signature.Signer;
import com.mirkocaserta.bruce.signature.Verifier;
import com.mirkocaserta.bruce.signature.VerifierByKey;

import java.nio.charset.Charset;
import java.security.*;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Implementation class for signature operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class SignatureOperations {
    
    private static final String BLANK = "";
    
    private SignatureOperations() {
        // utility class
    }
    
    /**
     * Creates a signer using the default provider.
     *
     * @param privateKey the private key
     * @param algorithm the signature algorithm (e.g., SHA256withRSA)
     * @return a signer producing raw bytes
     */
    public static Signer createSigner(PrivateKey privateKey, String algorithm) {
        return createSigner(privateKey, algorithm, BLANK);
    }
    
    /**
     * Creates a signer using a specific provider.
     *
     * @param privateKey the private key
     * @param algorithm the signature algorithm
     * @param provider the JCA provider name
     * @return a signer producing raw bytes
     */
    public static Signer createSigner(PrivateKey privateKey, String algorithm, String provider) {
        Signer signer = message -> {
            try {
                var signature = getSignature(algorithm, provider);
                signature.initSign(privateKey);
                signature.update(message);
                return signature.sign();
            } catch (SignatureException | InvalidKeyException e) {
                throw new BruceException(String.format("error generating the signature: algorithm=%s, provider=%s", algorithm, provider), e);
            }
        };

        /*
        This is here in order to trigger exceptions at initialization time
        rather than at runtime when invoking the sign method on the signer.
         */
        signer.sign("FAIL FAST".getBytes(UTF_8));
        return signer;
    }
    
    /**
     * Creates a signer with runtime key selection.
     *
     * @param privateKeyMap map of key id to private key
     * @param algorithm the signature algorithm
     * @return a signer with runtime key selection
     */
    public static SignerByKey createSignerByKey(Map<String, PrivateKey> privateKeyMap, String algorithm) {
        return createSignerByKey(privateKeyMap, algorithm, BLANK);
    }
    
    /**
     * Creates a signer with runtime key selection using a specific provider.
     *
     * @param privateKeyMap map of key id to private key
     * @param algorithm the signature algorithm
     * @param provider the JCA provider name
     * @return a signer with runtime key selection
     */
    public static SignerByKey createSignerByKey(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider) {
        return (privateKeyId, message) -> {
            var privateKey = privateKeyMap.get(privateKeyId);

            if (privateKey == null) {
                throw new BruceException(String.format("private key not found for id: %s", privateKeyId));
            }

            return createSigner(privateKey, algorithm, provider).sign(message);
        };
    }
    
    /**
     * Creates an encoding signer with runtime key selection using the default provider and UTF-8 charset.
     *
     * @param privateKeyMap map of key id to private key
     * @param algorithm the signature algorithm
     * @param encoding the signature encoding
     * @return an encoding signer with runtime key selection
     */
    public static EncodingSignerByKey createEncodingSignerByKey(Map<String, PrivateKey> privateKeyMap, String algorithm, Bruce.Encoding encoding) {
        return createEncodingSignerByKey(privateKeyMap, algorithm, null, UTF_8, encoding);
    }
    
    /**
     * Creates an encoding signer with runtime key selection and custom charset.
     *
     * @param privateKeyMap map of key id to private key
     * @param algorithm the signature algorithm
     * @param charset the input charset
     * @param encoding the signature encoding
     * @return an encoding signer with runtime key selection
     */
    public static EncodingSignerByKey createEncodingSignerByKey(Map<String, PrivateKey> privateKeyMap, String algorithm, Charset charset, Bruce.Encoding encoding) {
        return createEncodingSignerByKey(privateKeyMap, algorithm, null, charset, encoding);
    }
    
    /**
     * Creates an encoding signer with runtime key selection using a specific provider and custom charset.
     *
     * @param privateKeyMap map of key id to private key
     * @param algorithm the signature algorithm
     * @param provider the JCA provider name
     * @param charset the input charset
     * @param encoding the signature encoding
     * @return an encoding signer with runtime key selection
     */
    public static EncodingSignerByKey createEncodingSignerByKey(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return (privateKeyId, message) -> {
            var privateKey = privateKeyMap.get(privateKeyId);

            if (privateKey == null) {
                throw new BruceException(String.format("private key not found for id: %s", privateKeyId));
            }

            return createEncodingSigner(privateKey, algorithm, provider, charset, encoding).sign(message);
        };
    }
    
    /**
     * Creates an encoding signer using the default provider and UTF-8 charset.
     *
     * @param privateKey the private key
     * @param algorithm the signature algorithm
     * @param encoding the signature encoding
     * @return an encoding signer
     */
    public static EncodingSigner createEncodingSigner(PrivateKey privateKey, String algorithm, Bruce.Encoding encoding) {
        return createEncodingSigner(privateKey, algorithm, BLANK, UTF_8, encoding);
    }
    
    /**
     * Creates an encoding signer using the default provider and custom charset.
     *
     * @param privateKey the private key
     * @param algorithm the signature algorithm
     * @param charset the input charset
     * @param encoding the signature encoding
     * @return an encoding signer
     */
    public static EncodingSigner createEncodingSigner(PrivateKey privateKey, String algorithm, Charset charset, Bruce.Encoding encoding) {
        return createEncodingSigner(privateKey, algorithm, BLANK, charset, encoding);
    }
    
    /**
     * Creates an encoding signer using a specific provider and custom charset.
     *
     * @param privateKey the private key
     * @param algorithm the signature algorithm
     * @param provider the JCA provider name
     * @param charset the input charset
     * @param encoding the signature encoding
     * @return an encoding signer
     */
    public static EncodingSigner createEncodingSigner(PrivateKey privateKey, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        if (encoding == null) {
            throw new BruceException("Invalid encoding: null");
        }

        if (charset == null) {
            throw new BruceException("Invalid charset: null");
        }

        var signer = createSigner(privateKey, algorithm, provider);
        return message -> EncodingUtils.encode(encoding, signer.sign(message.getBytes(charset)));
    }
    
    /**
     * Creates a verifier using the default provider.
     *
     * @param publicKey the public key
     * @param algorithm the signature algorithm
     * @return a verifier of raw signature bytes
     */
    public static Verifier createVerifier(PublicKey publicKey, String algorithm) {
        return createVerifier(publicKey, algorithm, BLANK);
    }
    
    /**
     * Creates a verifier using a specific provider.
     *
     * @param publicKey the public key
     * @param algorithm the signature algorithm
     * @param provider the JCA provider name
     * @return a verifier of raw signature bytes
     */
    public static Verifier createVerifier(PublicKey publicKey, String algorithm, String provider) {
        return (message, signature) -> {
            try {
                var signatureInstance = getSignature(algorithm, provider);
                signatureInstance.initVerify(publicKey);
                signatureInstance.update(message);
                return signatureInstance.verify(signature);
            } catch (InvalidKeyException e) {
                throw new BruceException(String.format("error verifying the signature: algorithm=%s, provider=%s", algorithm, provider), e);
            } catch (SignatureException e) {
                return false;
            }
        };
    }
    
    /**
     * Creates a verifier with runtime key selection.
     *
     * @param publicKeyMap map of key id to public key
     * @param algorithm the signature algorithm
     * @return a verifier with runtime key selection
     */
    public static VerifierByKey createVerifierByKey(Map<String, PublicKey> publicKeyMap, String algorithm) {
        return createVerifierByKey(publicKeyMap, algorithm, BLANK);
    }
    
    /**
     * Creates a verifier with runtime key selection using a specific provider.
     *
     * @param publicKeyMap map of key id to public key
     * @param algorithm the signature algorithm
     * @param provider the JCA provider name
     * @return a verifier with runtime key selection
     */
    public static VerifierByKey createVerifierByKey(Map<String, PublicKey> publicKeyMap, String algorithm, String provider) {
        return (publicKeyId, message, signature) -> {
            var publicKey = publicKeyMap.get(publicKeyId);

            if (publicKey == null) {
                throw new BruceException(String.format("public key not found for id: %s", publicKeyId));
            }

            return createVerifier(publicKey, algorithm, provider).verify(message, signature);
        };
    }
    
    /**
     * Creates an encoding verifier using the default provider and UTF-8 charset.
     *
     * @param publicKey the public key
     * @param algorithm the signature algorithm
     * @param encoding the signature encoding
     * @return an encoding verifier
     */
    public static EncodingVerifier createEncodingVerifier(PublicKey publicKey, String algorithm, Bruce.Encoding encoding) {
        return createEncodingVerifier(publicKey, algorithm, BLANK, encoding);
    }
    
    /**
     * Creates an encoding verifier using a specific provider and UTF-8 charset.
     *
     * @param publicKey the public key
     * @param algorithm the signature algorithm
     * @param provider the JCA provider name
     * @param encoding the signature encoding
     * @return an encoding verifier
     */
    public static EncodingVerifier createEncodingVerifier(PublicKey publicKey, String algorithm, String provider, Bruce.Encoding encoding) {
        return createEncodingVerifier(publicKey, algorithm, provider, UTF_8, encoding);
    }
    
    /**
     * Creates an encoding verifier using a specific provider and custom charset.
     *
     * @param publicKey the public key
     * @param algorithm the signature algorithm
     * @param provider the JCA provider name
     * @param charset the input charset
     * @param encoding the signature encoding
     * @return an encoding verifier
     */
    public static EncodingVerifier createEncodingVerifier(PublicKey publicKey, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        if (encoding == null) {
            throw new BruceException("Invalid encoding: null");
        }

        if (charset == null) {
            throw new BruceException("Invalid charset: null");
        }

        var verifier = createVerifier(publicKey, algorithm, provider);
        return (message, signature) -> verifier.verify(message.getBytes(charset), EncodingUtils.decode(encoding, signature));
    }
    
    /**
     * Creates an encoding verifier with runtime key selection using the default provider and UTF-8 charset.
     *
     * @param publicKeyMap map of key id to public key
     * @param algorithm the signature algorithm
     * @param encoding the signature encoding
     * @return an encoding verifier with runtime key selection
     */
    public static EncodingVerifierByKey createEncodingVerifierByKey(Map<String, PublicKey> publicKeyMap, String algorithm, Bruce.Encoding encoding) {
        return createEncodingVerifierByKey(publicKeyMap, algorithm, null, UTF_8, encoding);
    }
    
    /**
     * Creates an encoding verifier with runtime key selection and custom charset.
     *
     * @param publicKeyMap map of key id to public key
     * @param algorithm the signature algorithm
     * @param charset the input charset
     * @param encoding the signature encoding
     * @return an encoding verifier with runtime key selection
     */
    public static EncodingVerifierByKey createEncodingVerifierByKey(Map<String, PublicKey> publicKeyMap, String algorithm, Charset charset, Bruce.Encoding encoding) {
        return createEncodingVerifierByKey(publicKeyMap, algorithm, null, charset, encoding);
    }
    
    /**
     * Creates an encoding verifier with runtime key selection using a specific provider and custom charset.
     *
     * @param publicKeyMap map of key id to public key
     * @param algorithm the signature algorithm
     * @param provider the JCA provider name
     * @param charset the input charset
     * @param encoding the signature encoding
     * @return an encoding verifier with runtime key selection
     */
    public static EncodingVerifierByKey createEncodingVerifierByKey(Map<String, PublicKey> publicKeyMap, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return (publicKeyId, message, signature) -> {
            var publicKey = publicKeyMap.get(publicKeyId);

            if (publicKey == null) {
                throw new BruceException(String.format("public key not found for id: %s", publicKeyId));
            }

            return createEncodingVerifier(publicKey, algorithm, provider, charset, encoding).verify(message, signature);
        };
    }
    
    private static Signature getSignature(String algorithm, String provider) {
        try {
            return provider == null || provider.isBlank()
                    ? Signature.getInstance(algorithm)
                    : Signature.getInstance(algorithm, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new BruceException(String.format("error getting signer: algorithm=%s, provider=%s", algorithm, provider), e);
        }
    }
}