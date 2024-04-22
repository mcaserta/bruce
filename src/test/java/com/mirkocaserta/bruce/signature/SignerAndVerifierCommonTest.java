package com.mirkocaserta.bruce.signature;

import static java.lang.System.currentTimeMillis;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.CompletableFuture.supplyAsync;
import static org.junit.jupiter.api.Assertions.*;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.stream.IntStream;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

public abstract class SignerAndVerifierCommonTest {

  private final Signer signer = getSigner();
  private final Verifier verifier = getVerifier();

  protected abstract Signer getSigner();

  protected abstract Verifier getVerifier();

  @Test
  void signAndVerify() {
    byte[] message = "this is a top-secret message".getBytes(UTF_8);
    byte[] signature = signer.sign(message);
    assertNotNull(signature);
    assertTrue(verifier.verify(message, signature));
  }

  @RepeatedTest(10)
  void signAndVerifyRepeated() {
    final byte[] message = UUID.randomUUID().toString().getBytes(UTF_8);
    byte[] signature = signer.sign(message);
    assertNotNull(signature);
    assertTrue(verifier.verify(message, signature));
  }

  @Test
  void signAndVerifyConcurrently() {
    long start = currentTimeMillis();
    CompletableFuture<?>[] futures = new CompletableFuture[100];

    IntStream.range(0, futures.length)
        .forEach(
            i -> {
              final byte[] message = UUID.randomUUID().toString().getBytes(UTF_8);
              CompletableFuture<byte[]> signatureFuture = supplyAsync(() -> signer.sign(message));
              assertNotNull(signatureFuture);
              CompletableFuture<Boolean> verifierFuture =
                  signatureFuture.thenApply(signature -> verifier.verify(message, signature));
              futures[i] = verifierFuture;
            });

    CompletableFuture.allOf(futures); // let all threads do their job

    for (CompletableFuture<?> future : futures) {
      assertTrue((boolean) future.join());
    }

    System.out.printf(
        "%d sign and verify cycles completed concurrently in %d milliseconds\n",
        futures.length, currentTimeMillis() - start);
  }

  @Test
  void verifyWithGarbageSignatureFails() {
    byte[] message = "this is a top-secret message".getBytes(UTF_8);
    assertFalse(verifier.verify(message, "garbage".getBytes(UTF_8)));
  }

  @Test
  void verifyWithTamperedMessageFails() {
    byte[] message = "this is a top-secret message".getBytes(UTF_8);
    byte[] signature = signer.sign(message);
    assertNotNull(signature);
    assertFalse(verifier.verify(new byte[] {1, 2, 3}, signature));
  }
}
