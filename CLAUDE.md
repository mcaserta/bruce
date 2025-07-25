# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bruce is an ergonomic, lightweight, pure Java wrapper around the Java Cryptography API (JCA). It provides simplified
interfaces for common cryptographic operations including:

- Digital signatures and verification
- Symmetric and asymmetric encryption/decryption
- Message digests and file hashing
- Message Authentication Codes (MAC)
- Keystore operations and key management
- Support for multiple encodings (HEX, BASE64, URL, MIME)

## Build System & Commands

This is a Java library project using Gradle with Java 17 as the target version.

### Essential Commands

- `./gradlew build` - Full build including compilation, tests, and JAR creation
- `./gradlew test` - Run all JUnit tests
- `./gradlew clean` - Clean build artifacts
- `./gradlew javadoc` - Generate API documentation
- `./gradlew jacocoTestReport` - Generate code coverage report
- `./gradlew publishToMavenLocal` - Publish to local Maven repository

### Testing

- Tests use JUnit 5 (Jupiter)
- Mockito for mocking (v5.18.0)
- Bouncy Castle provider for some advanced cryptographic tests
- All tests are in `src/test/java/` with the same package structure as main code
- Test resources (keystores, certificates) are in `src/test/resources/`

### Quality Tools

- SonarQube integration for code analysis (`./gradlew sonar`)
- JaCoCo for test coverage reporting
- Uses Java modules (module-info.java)

## Architecture

The library follows a facade pattern with `Bruce.java` as the main entry point. All cryptographic operations are
accessed through static methods on the `Bruce` class.

### Core Components

**Main Entry Point:**

- `Bruce.java` - Central facade providing static factory methods for all cryptographic operations

**Package Structure:**

- `cipher/` - Encryption/decryption operations
    - `asymmetric/` - RSA, DSA public/private key encryption
    - `symmetric/` - AES, DES secret key encryption
- `digest/` - Message digests (SHA, MD5, etc.)
- `mac/` - Message Authentication Codes
- `signature/` - Digital signing and verification
- `util/` - Utilities like hex encoding

### Key Design Patterns

**Functional Interfaces:**
Most operations return functional interfaces (e.g., `Signer`, `Verifier`, `Cipher`) that can be used fluently.

**Builder Pattern (NEW):**
Complex operations with many parameters now support fluent builder APIs to reduce parameter overload:
- `Bruce.cipherBuilder()` - for cipher operations with 6+ parameters
- `Bruce.signerBuilder()` - for signer operations with 5+ parameters

**Multiple Key Support:**
Many operations support "ByKey" variants that accept a Map of keys, allowing runtime key selection by ID.

**Encoding Support:**
Operations that work with text support multiple encodings via the `Encoding` enum (HEX, BASE64, URL, MIME).

**Provider Support:**
All operations support pluggable cryptographic providers (defaults to system, but can specify Bouncy Castle "BC" or
others).

### Dependencies

**Runtime:**

- Pure JDK - no external runtime dependencies
- Uses standard JCA (Java Cryptography Architecture)

**Test-only:**

- Bouncy Castle (`bcprov-jdk15on`) for extended cryptographic algorithm testing
- JUnit 5 for testing framework
- Mockito for mocking

## Module System

The project uses Java 9+ modules defined in `module-info.java`. Exports all public API packages but keeps internal
implementation details private.