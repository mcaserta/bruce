# Refactoring TODOs

- [ ] Split `Bruce` facade into feature-focused facades (cipher, signature, digest, mac, keystore); keep `Bruce` as thin static forwarder for backward compatibility.
- [ ] Deprecate overload-heavy static APIs in favor of builders (`cipherBuilder()`, `signerBuilder()`, `verifierBuilder()`, `digestBuilder()`, `macBuilder()`); add `@Deprecated` with Javadoc pointing to builders.
- [ ] Rename `com.mirkocaserta.bruce.cipher.asymmetric.Cipher` and `com.mirkocaserta.bruce.cipher.symmetric.Cipher` to `AsymmetricCipher` and `SymmetricCipher` to avoid confusion with `java.security.Cipher`; provide deprecated type aliases for one release.
- [ ] Consolidate encoding/charset/provider overloads via builders to reduce duplication (prefer single builder with optional `provider`, `encoding`, `charset`).
- [ ] Extract a `KeyStoreSource` strategy (classpath/file/http/https) and move protocol parsing out of operations; unit-test each source.
- [ ] Centralize provider handling: add `Providers.resolve(String name): Provider` and pass `Provider` internally instead of `String`.
- [ ] Add `@FunctionalInterface` where applicable (`Signer`, `Verifier`, `Mac`, `Digester`).
- [ ] Introduce argument validation utilities (e.g., `Preconditions`) for null/empty checks; standardize `BruceException` messages.
- [ ] Ensure builders are immutable or defensively copy state on build; validate required parameters early.
- [ ] Prefer `char[]` over `String` for passwords/keys; keep `String` overloads as convenience delegating to secure forms.
- [ ] Add streaming variants for signing/verifying and MAC (accept `InputStream`), analogous to `FileDigester`.
- [ ] Review `module-info.java` exports; keep `impl` internal; consider relocating `Mode` to a neutral API package to avoid exporting parent `cipher` solely for it.
- [ ] Normalize parameter ordering across APIs: `(key|keys), algorithm, provider?, mode?, encoding?, charset?`.
- [ ] Gradle: use Java toolchain (17), adopt `junit-bom`, collapse JUnit deps, and configure reproducible builds.
- [ ] Add formatting/linting (Spotless) and static analysis (Error Prone); wire to CI and `./gradlew build`.
