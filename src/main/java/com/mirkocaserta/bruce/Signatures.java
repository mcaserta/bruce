package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.impl.signature.SignatureOperations;
import com.mirkocaserta.bruce.signature.EncodingSigner;
import com.mirkocaserta.bruce.signature.EncodingSignerByKey;
import com.mirkocaserta.bruce.signature.EncodingVerifier;
import com.mirkocaserta.bruce.signature.EncodingVerifierByKey;
import com.mirkocaserta.bruce.signature.Signer;
import com.mirkocaserta.bruce.signature.SignerByKey;
import com.mirkocaserta.bruce.signature.Verifier;
import com.mirkocaserta.bruce.signature.VerifierByKey;

import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

/**
 * Feature-focused facade for signature and verification operations.
 */
public final class Signatures {

    private Signatures() {
        // utility class
    }

    public static Signer signer(PrivateKey privateKey, String algorithm) {
        return SignatureOperations.createSigner(privateKey, algorithm);
    }

    public static Signer signer(PrivateKey privateKey, String algorithm, String provider) {
        return SignatureOperations.createSigner(privateKey, algorithm, provider);
    }

    public static SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm) {
        return SignatureOperations.createSignerByKey(privateKeyMap, algorithm);
    }

    public static SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider) {
        return SignatureOperations.createSignerByKey(privateKeyMap, algorithm, provider);
    }

    public static EncodingSignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingSignerByKey(privateKeyMap, algorithm, encoding);
    }

    public static EncodingSignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, Charset charset, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingSignerByKey(privateKeyMap, algorithm, charset, encoding);
    }

    public static EncodingSignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingSignerByKey(privateKeyMap, algorithm, provider, charset, encoding);
    }

    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingSigner(privateKey, algorithm, encoding);
    }

    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, Charset charset, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingSigner(privateKey, algorithm, charset, encoding);
    }

    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingSigner(privateKey, algorithm, provider, charset, encoding);
    }

    public static Verifier verifier(PublicKey publicKey, String algorithm) {
        return SignatureOperations.createVerifier(publicKey, algorithm);
    }

    public static Verifier verifier(PublicKey publicKey, String algorithm, String provider) {
        return SignatureOperations.createVerifier(publicKey, algorithm, provider);
    }

    public static VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm) {
        return SignatureOperations.createVerifierByKey(publicKeyMap, algorithm);
    }

    public static VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, String provider) {
        return SignatureOperations.createVerifierByKey(publicKeyMap, algorithm, provider);
    }

    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingVerifier(publicKey, algorithm, encoding);
    }

    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, String provider, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingVerifier(publicKey, algorithm, provider, encoding);
    }

    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingVerifier(publicKey, algorithm, provider, charset, encoding);
    }

    public static EncodingVerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingVerifierByKey(publicKeyMap, algorithm, encoding);
    }

    public static EncodingVerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, Charset charset, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingVerifierByKey(publicKeyMap, algorithm, charset, encoding);
    }

    public static EncodingVerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return SignatureOperations.createEncodingVerifierByKey(publicKeyMap, algorithm, provider, charset, encoding);
    }
}
