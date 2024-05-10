package com.mirkocaserta.bruce.mac;

import static com.mirkocaserta.bruce.Bruce.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.mirkocaserta.bruce.Bruce;
import java.security.Key;
import java.security.KeyStore;
import org.junit.jupiter.api.Test;

class MacRoundTripTest {

  private static final KeyStore keystore =
      Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");

  private static final Key key = Bruce.secretKey.with(keystore, "hmac", "password".toCharArray());

  @Test
  void roundTrip() {
    Mac alice = mac(key, "HmacSHA1");
    assertNotNull(alice);
    Mac bob = mac(key, "HmacSHA1");
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
