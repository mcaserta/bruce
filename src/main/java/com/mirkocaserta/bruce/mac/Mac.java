package com.mirkocaserta.bruce.mac;

import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.impl.util.Preconditions;

import java.security.MessageDigest;


/**
 * Unified contract for producing and verifying Message Authentication Codes.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes tag = mac.get(Bytes.from("message"));
 * String base64 = tag.encode(Bruce.Encoding.BASE64);
 *
 * // on the receiving side
 * boolean authentic = mac.verify(Bytes.from("message"), Bytes.from(base64, Bruce.Encoding.BASE64));
 * }</pre>
 *
 * @author Mirko Caserta (info@mirkocaserta.com)
 */
@FunctionalInterface
public interface Mac {

    /**
     * Computes the MAC for the given input message.
     *
     * @param message the input message
     * @return the MAC wrapped in {@link Bytes}
     */
    Bytes get(Bytes message);

    /**
     * Verifies that {@code tag} is the MAC of {@code message}.
     *
     * <p>The MAC is recomputed with {@link #get(Bytes)} and compared to
     * {@code tag} using {@link MessageDigest#isEqual(byte[], byte[])}, whose
     * running time does not depend on where the two values first differ.
     * Use this method, not {@link Bytes#equals(Object)}, to check a received
     * tag: an early-exit comparison leaks timing information that can help an
     * attacker forge a valid tag.</p>
     *
     * @param message the message the tag is claimed to authenticate
     * @param tag     the received MAC
     * @return {@code true} if {@code tag} matches the MAC of {@code message},
     *         {@code false} otherwise (including when the lengths differ)
     * @throws com.mirkocaserta.bruce.BruceException if {@code message} or
     *         {@code tag} is {@code null}
     */
    default boolean verify(Bytes message, Bytes tag) {
        Preconditions.requireNonNull(message, "message");
        Preconditions.requireNonNull(tag, "tag");
        return MessageDigest.isEqual(get(message).asBytes(), tag.asBytes());
    }

}
