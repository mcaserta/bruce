package com.mirkocaserta.bruce.mac;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import java.security.Key;
import java.security.KeyStore;
import org.junit.jupiter.api.Test;

class EncodingMacRoundTripTest {

  private static final KeyStore keystore =
      keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");

  private static final Key key = secretKey(keystore, "hmac", "password".toCharArray());

  @Test
  void roundTrip() {
    EncodingMac alice = mac(key, "HmacSHA1", BASE64, UTF_8);
    assertNotNull(alice);
    EncodingMac bob = mac(key, "HmacSHA1", BASE64, UTF_8);
    assertNotNull(bob);

    String message = "Hello there";
    String aliceMac = alice.get(message);
    assertNotNull(aliceMac);
    assertFalse(aliceMac.isBlank());
    String bobMac = bob.get(message);
    assertNotNull(bobMac);
    assertFalse(bobMac.isBlank());
    assertEquals(aliceMac, bobMac);
  }
}
