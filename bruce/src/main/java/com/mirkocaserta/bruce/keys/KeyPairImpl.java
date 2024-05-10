package com.mirkocaserta.bruce.keys;

import com.mirkocaserta.bruce.BruceException;
import java.security.*;

public final class KeyPairImpl implements com.mirkocaserta.bruce.api.KeyPair {
  @Override
  public KeyPair with(final String algorithm, final int keySize) {
    return with(algorithm, null, keySize, null);
  }

  @Override
  public KeyPair with(final String algorithm, final String provider, final int keySize) {
    return with(algorithm, provider, keySize, null);
  }

  @Override
  public KeyPair with(final String algorithm, final int keySize, final SecureRandom random) {
    return with(algorithm, null, keySize, random);
  }

  @Override
  public KeyPair with(
      final String algorithm, final String provider, final int keySize, final SecureRandom random) {
    try {
      final var keyGen =
          provider == null || provider.isBlank()
              ? KeyPairGenerator.getInstance(algorithm)
              : KeyPairGenerator.getInstance(algorithm, provider);

      if (random == null) {
        keyGen.initialize(keySize);
      } else {
        keyGen.initialize(keySize, random);
      }
      return keyGen.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new BruceException(String.format("no such algorithm: %s", algorithm), e);
    } catch (InvalidParameterException e) {
      throw new BruceException(String.format("invalid key size: %d", keySize), e);
    } catch (NoSuchProviderException e) {
      throw new BruceException(String.format("no such provider: %s", provider), e);
    }
  }
}
