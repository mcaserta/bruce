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
    
    public static Signer createSigner(PrivateKey privateKey, String algorithm) {
        return createSigner(privateKey, algorithm, BLANK);
    }
    
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
    
    public static SignerByKey createSignerByKey(Map<String, PrivateKey> privateKeyMap, String algorithm) {
        return createSignerByKey(privateKeyMap, algorithm, BLANK);
    }
    
    public static SignerByKey createSignerByKey(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider) {
        return (privateKeyId, message) -> {
            var privateKey = privateKeyMap.get(privateKeyId);

            if (privateKey == null) {
                throw new BruceException(String.format("private key not found for id: %s", privateKeyId));
            }

            return createSigner(privateKey, algorithm, provider).sign(message);
        };
    }
    
    public static EncodingSignerByKey createEncodingSignerByKey(Map<String, PrivateKey> privateKeyMap, String algorithm, Bruce.Encoding encoding) {
        return createEncodingSignerByKey(privateKeyMap, algorithm, null, UTF_8, encoding);
    }
    
    public static EncodingSignerByKey createEncodingSignerByKey(Map<String, PrivateKey> privateKeyMap, String algorithm, Charset charset, Bruce.Encoding encoding) {
        return createEncodingSignerByKey(privateKeyMap, algorithm, null, charset, encoding);
    }
    
    public static EncodingSignerByKey createEncodingSignerByKey(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return (privateKeyId, message) -> {
            var privateKey = privateKeyMap.get(privateKeyId);

            if (privateKey == null) {
                throw new BruceException(String.format("private key not found for id: %s", privateKeyId));
            }

            return createEncodingSigner(privateKey, algorithm, provider, charset, encoding).sign(message);
        };
    }
    
    public static EncodingSigner createEncodingSigner(PrivateKey privateKey, String algorithm, Bruce.Encoding encoding) {
        return createEncodingSigner(privateKey, algorithm, BLANK, UTF_8, encoding);
    }
    
    public static EncodingSigner createEncodingSigner(PrivateKey privateKey, String algorithm, Charset charset, Bruce.Encoding encoding) {
        return createEncodingSigner(privateKey, algorithm, BLANK, charset, encoding);
    }
    
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
    
    public static Verifier createVerifier(PublicKey publicKey, String algorithm) {
        return createVerifier(publicKey, algorithm, BLANK);
    }
    
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
    
    public static VerifierByKey createVerifierByKey(Map<String, PublicKey> publicKeyMap, String algorithm) {
        return createVerifierByKey(publicKeyMap, algorithm, BLANK);
    }
    
    public static VerifierByKey createVerifierByKey(Map<String, PublicKey> publicKeyMap, String algorithm, String provider) {
        return (publicKeyId, message, signature) -> {
            var publicKey = publicKeyMap.get(publicKeyId);

            if (publicKey == null) {
                throw new BruceException(String.format("public key not found for id: %s", publicKeyId));
            }

            return createVerifier(publicKey, algorithm, provider).verify(message, signature);
        };
    }
    
    public static EncodingVerifier createEncodingVerifier(PublicKey publicKey, String algorithm, Bruce.Encoding encoding) {
        return createEncodingVerifier(publicKey, algorithm, BLANK, encoding);
    }
    
    public static EncodingVerifier createEncodingVerifier(PublicKey publicKey, String algorithm, String provider, Bruce.Encoding encoding) {
        return createEncodingVerifier(publicKey, algorithm, provider, UTF_8, encoding);
    }
    
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
    
    public static EncodingVerifierByKey createEncodingVerifierByKey(Map<String, PublicKey> publicKeyMap, String algorithm, Bruce.Encoding encoding) {
        return createEncodingVerifierByKey(publicKeyMap, algorithm, null, UTF_8, encoding);
    }
    
    public static EncodingVerifierByKey createEncodingVerifierByKey(Map<String, PublicKey> publicKeyMap, String algorithm, Charset charset, Bruce.Encoding encoding) {
        return createEncodingVerifierByKey(publicKeyMap, algorithm, null, charset, encoding);
    }
    
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