package com.mirkocaserta.bruce.signature;

import static java.lang.System.currentTimeMillis;
import static java.util.concurrent.CompletableFuture.supplyAsync;
import static org.junit.jupiter.api.Assertions.*;

import com.mirkocaserta.bruce.BruceException;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.stream.IntStream;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

public abstract class EncodingSignerAndVerifierCommonTest {

  private final Signer signer = getSigner();
  private final Verifier verifier = getVerifier();

  protected abstract Signer getSigner();

  protected abstract Verifier getVerifier();

  @Test
  void signAndVerify() {
    String message = "this is a top-secret message";
    String signature = signer.sign(message);
    assertNotNull(signature);
    assertTrue(verifier.verify(message, signature));
  }

  @RepeatedTest(10)
  void signAndVerifyRepeated() {
    String message = UUID.randomUUID().toString();
    String signature = signer.sign(message);
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
              String message = UUID.randomUUID().toString();
              CompletableFuture<String> signatureFuture = supplyAsync(() -> signer.sign(message));
              assertNotNull(signatureFuture);
              futures[i] =
                  signatureFuture.thenApply(signature -> verifier.verify(message, signature));
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
    String message = "this is a top-secret message";
    assertFalse(verifier.verify(message, "cafebabe"));
  }

  @Test
  void verifyWithTamperedMessageFails() {
    String message = "this is a top-secret message";
    String signature = signer.sign(message);
    assertNotNull(signature);
    assertFalse(verifier.verify("sgiao belo", signature));
  }

  @Test
  void verifyWithGarbageInputFails() {
    String message = "this is a top-secret message";
    assertThrows(BruceException.class, () -> verifier.verify(message, "sgiao belo"));
  }
}
