package com.mirkocaserta.bruce.cipher.symmetric;

import static com.mirkocaserta.bruce.Bruce.symmetricKey;
import static com.mirkocaserta.bruce.cipher.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.mirkocaserta.bruce.Bruce;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class CipherRoundTripWithCustomProviderTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  void roundTrip() {
    Random rng = new SecureRandom();
    byte[] iv = new byte[8];
    rng.nextBytes(iv);
    byte[] key = symmetricKey("DESede", "BC");
    Cipher encrypter = Bruce.cipher(key, "DESede", "DESede/CBC/PKCS5Padding", "BC", ENCRYPT);
    Cipher decrypter = Bruce.cipher(key, "DESede", "DESede/CBC/PKCS5Padding", "BC", DECRYPT);
    byte[] plainText = "Hi there".getBytes(UTF_8);
    byte[] cypherText = encrypter.encrypt(iv, plainText);
    assertNotNull(cypherText);
    byte[] decryptedText = decrypter.encrypt(iv, cypherText);
    assertNotNull(decryptedText);
    assertArrayEquals(plainText, decryptedText);
  }
}
