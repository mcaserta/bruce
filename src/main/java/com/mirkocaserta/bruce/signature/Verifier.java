package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Unified contract for verifying digital signatures across raw and encoded representations.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface Verifier {

    Charset charset();

    Bruce.Encoding encoding();

    boolean verify(byte[] message, byte[] signature);

    default boolean verify(String message, Charset charset, byte[] signature) {
        return verify(message.getBytes(charset), signature);
    }

    default boolean verify(String message, byte[] signature) {
        return verify(message, charset(), signature);
    }

    default boolean verify(byte[] message, String signature, Bruce.Encoding encoding) {
        return verify(message, EncodingUtils.decode(encoding, signature));
    }

    default boolean verify(byte[] message, String signature) {
        return verify(message, signature, encoding());
    }

    default boolean verify(String message, Charset charset, String signature, Bruce.Encoding encoding) {
        return verify(message.getBytes(charset), EncodingUtils.decode(encoding, signature));
    }

    default boolean verify(String message, Charset charset, String signature) {
        return verify(message, charset, signature, encoding());
    }

    default boolean verify(String message, String signature, Bruce.Encoding encoding) {
        return verify(message, charset(), signature, encoding);
    }

    default boolean verify(String message, String signature) {
        return verify(message, charset(), signature, encoding());
    }

    /**
     * Verifies a signature where both message and signature are represented as {@link Bytes}.
     *
     * @param message   the original message
     * @param signature the signature to verify
     * @return {@code true} if the signature is valid
     */
    default boolean verify(Bytes message, Bytes signature) {
        return verify(message.asBytes(), signature.asBytes());
    }
}
