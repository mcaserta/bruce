package com.mirkocaserta.bruce.impl.signature;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.impl.util.Providers;
import com.mirkocaserta.bruce.signature.Signer;
import com.mirkocaserta.bruce.signature.SignerByKey;
import com.mirkocaserta.bruce.signature.Verifier;
import com.mirkocaserta.bruce.signature.VerifierByKey;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Map;

/**
 * Implementation class for signature operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class SignatureOperations {

    private SignatureOperations() {
        // utility class
    }

    public static Signer createSigner(PrivateKey privateKey, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        Provider resolvedProvider = Providers.resolve(provider);
        failFast(privateKey, algorithm, resolvedProvider);

        return new Signer() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] sign(byte[] message) {
                String providerName = resolvedProvider == null ? "" : resolvedProvider.getName();
                try {
                    var signature = getSignature(algorithm, resolvedProvider);
                    signature.initSign(privateKey);
                    signature.update(message);
                    return signature.sign();
                } catch (SignatureException | InvalidKeyException e) {
                    throw new BruceException(String.format("error generating the signature: algorithm=%s, provider=%s", algorithm, providerName), e);
                }
            }
        };
    }

    public static SignerByKey createSignerByKey(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        Provider resolvedProvider = Providers.resolve(provider);

        return new SignerByKey() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] sign(String privateKeyId, byte[] message) {
                var privateKey = privateKeyMap.get(privateKeyId);
                if (privateKey == null) {
                    throw new BruceException(String.format("private key not found for id: %s", privateKeyId));
                }
                return createSigner(privateKey, algorithm, provider, charset, encoding).sign(message);
            }
        };
    }

    public static Verifier createVerifier(PublicKey publicKey, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        Provider resolvedProvider = Providers.resolve(provider);
        failFast(publicKey, algorithm, resolvedProvider);

        return new Verifier() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public boolean verify(byte[] message, byte[] signatureBytes) {
                String providerName = resolvedProvider == null ? "" : resolvedProvider.getName();
                try {
                    var signature = getSignature(algorithm, resolvedProvider);
                    signature.initVerify(publicKey);
                    signature.update(message);
                    return signature.verify(signatureBytes);
                } catch (InvalidKeyException e) {
                    throw new BruceException(String.format("error verifying the signature: algorithm=%s, provider=%s", algorithm, providerName), e);
                } catch (SignatureException e) {
                    return false;
                }
            }
        };
    }

    public static VerifierByKey createVerifierByKey(Map<String, PublicKey> publicKeyMap, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        Provider resolvedProvider = Providers.resolve(provider);

        return new VerifierByKey() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public boolean verify(String publicKeyId, byte[] message, byte[] signatureBytes) {
                var publicKey = publicKeyMap.get(publicKeyId);
                if (publicKey == null) {
                    throw new BruceException(String.format("public key not found for id: %s", publicKeyId));
                }
                return createVerifier(publicKey, algorithm, provider, charset, encoding).verify(message, signatureBytes);
            }
        };
    }

    private static Signature getSignature(String algorithm, Provider provider) {
        String providerName = provider == null ? "" : provider.getName();
        try {
            return provider == null
                    ? Signature.getInstance(algorithm)
                    : Signature.getInstance(algorithm, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new BruceException(String.format("error getting signer: algorithm=%s, provider=%s", algorithm, providerName), e);
        }
    }

    private static void failFast(PrivateKey privateKey, String algorithm, Provider provider) {
        String providerName = provider == null ? "" : provider.getName();
        try {
            var signature = getSignature(algorithm, provider);
            signature.initSign(privateKey);
            signature.update("FAIL FAST".getBytes(Bruce.DEFAULT_CHARSET));
            signature.sign();
        } catch (InvalidKeyException | SignatureException e) {
            throw new BruceException(String.format("error generating the signature: algorithm=%s, provider=%s", algorithm, providerName), e);
        }
    }

    private static void failFast(PublicKey publicKey, String algorithm, Provider provider) {
        String providerName = provider == null ? "" : provider.getName();
        try {
            var signature = getSignature(algorithm, provider);
            signature.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            throw new BruceException(String.format("error verifying the signature: algorithm=%s, provider=%s", algorithm, providerName), e);
        }
    }
}
