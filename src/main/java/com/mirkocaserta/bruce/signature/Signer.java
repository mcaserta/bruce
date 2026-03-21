package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Unified contract for producing digital signatures.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface Signer {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] sign(byte[] message);

    default byte[] sign(String message, Charset charset) {
        return sign(message.getBytes(charset));
    }

    default byte[] sign(String message) {
        return sign(message, charset());
    }

    default String signToString(byte[] message, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, sign(message));
    }

    default String signToString(byte[] message) {
        return signToString(message, encoding());
    }

    default String signToString(String message, Charset charset, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, sign(message, charset));
    }

    default String signToString(String message, Charset charset) {
        return signToString(message, charset, encoding());
    }

    default String signToString(String message, Bruce.Encoding encoding) {
        return signToString(message, charset(), encoding);
    }

    default String signToString(String message) {
        return signToString(message, charset(), encoding());
    }
}
