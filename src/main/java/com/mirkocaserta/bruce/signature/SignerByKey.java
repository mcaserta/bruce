package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Unified contract for producing digital signatures where the signing key is selected at runtime.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface SignerByKey {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] sign(String privateKeyId, byte[] message);

    default byte[] sign(String privateKeyId, String message, Charset charset) {
        return sign(privateKeyId, message.getBytes(charset));
    }

    default byte[] sign(String privateKeyId, String message) {
        return sign(privateKeyId, message, charset());
    }

    default String signToString(String privateKeyId, byte[] message, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, sign(privateKeyId, message));
    }

    default String signToString(String privateKeyId, byte[] message) {
        return signToString(privateKeyId, message, encoding());
    }

    default String signToString(String privateKeyId, String message, Charset charset, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, sign(privateKeyId, message, charset));
    }

    default String signToString(String privateKeyId, String message, Charset charset) {
        return signToString(privateKeyId, message, charset, encoding());
    }

    default String signToString(String privateKeyId, String message, Bruce.Encoding encoding) {
        return signToString(privateKeyId, message, charset(), encoding);
    }

    default String signToString(String privateKeyId, String message) {
        return signToString(privateKeyId, message, charset(), encoding());
    }

    /**
     * Signs the given {@link Bytes} message with the key identified by {@code privateKeyId}
     * and returns the signature as {@link Bytes}.
     *
     * @param privateKeyId the key identifier
     * @param message      the message to sign
     * @return the raw signature wrapped in {@link Bytes}
     */
    default Bytes sign(String privateKeyId, Bytes message) {
        return Bytes.from(sign(privateKeyId, message.asBytes()));
    }
}
