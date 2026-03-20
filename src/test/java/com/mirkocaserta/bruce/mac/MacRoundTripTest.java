package com.mirkocaserta.bruce.mac;

import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.KeyStore;

import static com.mirkocaserta.bruce.Bruce.macBuilder;
import static com.mirkocaserta.bruce.Keystores.keystore;
import static com.mirkocaserta.bruce.Keystores.secretKey;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class MacRoundTripTest {

    private final static KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");

    private final static Key key = secretKey(keystore, "hmac", "password".toCharArray());

    @Test
    void roundTrip() {
        Mac alice = macBuilder().key(key).algorithm("HmacSHA1").buildRaw();
        assertNotNull(alice);
        Mac bob = macBuilder().key(key).algorithm("HmacSHA1").buildRaw();
        assertNotNull(bob);

        byte[] message = "Hello there".getBytes(UTF_8);
        byte[] aliceMac = alice.get(message);
        assertNotNull(aliceMac);
        assertTrue(aliceMac.length > 0);
        byte[] bobMac = bob.get(message);
        assertNotNull(bobMac);
        assertTrue(bobMac.length > 0);
        assertArrayEquals(aliceMac, bobMac);
    }

}
