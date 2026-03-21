package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Unified contract for verifying digital signatures where the verification key is selected at runtime.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface VerifierByKey {

    Charset charset();

    Bruce.Encoding encoding();

    boolean verify(String publicKeyId, byte[] message, byte[] signature);

    default boolean verify(String publicKeyId, String message, Charset charset, byte[] signature) {
        return verify(publicKeyId, message.getBytes(charset), signature);
    }

    default boolean verify(String publicKeyId, String message, byte[] signature) {
        return verify(publicKeyId, message, charset(), signature);
    }

    default boolean verify(String publicKeyId, byte[] message, String signature, Bruce.Encoding encoding) {
        return verify(publicKeyId, message, EncodingUtils.decode(encoding, signature));
    }

    default boolean verify(String publicKeyId, byte[] message, String signature) {
        return verify(publicKeyId, message, signature, encoding());
    }

    default boolean verify(String publicKeyId, String message, Charset charset, String signature, Bruce.Encoding encoding) {
        return verify(publicKeyId, message.getBytes(charset), EncodingUtils.decode(encoding, signature));
    }

    default boolean verify(String publicKeyId, String message, Charset charset, String signature) {
        return verify(publicKeyId, message, charset, signature, encoding());
    }

    default boolean verify(String publicKeyId, String message, String signature, Bruce.Encoding encoding) {
        return verify(publicKeyId, message, charset(), signature, encoding);
    }

    default boolean verify(String publicKeyId, String message, String signature) {
        return verify(publicKeyId, message, charset(), signature, encoding());
    }

    /**
     * Verifies a signature where both message and signature are represented as {@link Bytes}.
     *
     * @param publicKeyId the key identifier
     * @param message     the original message
     * @param signature   the signature to verify
     * @return {@code true} if the signature is valid
     */
    default boolean verify(String publicKeyId, Bytes message, Bytes signature) {
        return verify(publicKeyId, message.asBytes(), signature.asBytes());
    }
}
