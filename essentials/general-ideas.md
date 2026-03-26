---
description: Some general concepts apply to all functionalities in Bruce.
---

# General Concepts

## Algorithms

Algorithms supported by the default JCA provider are listed
[here](https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html).

Algorithms supported by the Bouncy Castle JCA provider are listed
[here](https://www.bouncycastle.org/specifications.html).

## Static Imports

Static imports are used throughout all examples. Keystore and key helpers live
in `Keystores`:

```java
import static com.mirkocaserta.bruce.Keystores.*;

KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
PrivateKey key    = privateKey(keystore, "alice", "password".toCharArray());
```

Builder factories and encoding constants live in `Bruce`:

```java
import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.Bruce.Encoding.*;

Digester digester = digestBuilder().algorithm("SHA-256").build();
Bytes hash = digester.digest(Bytes.from("hello"));
String hex = hash.encode(HEX);
```

You are of course free not to use static imports.

## Passwords

Bruce provides two options for password handling to balance security and
convenience:

**For maximum security**: Use `char[]` arrays. String instances might be stored
in permanent memory areas, and depending on implementation specifics, this could
potentially be accessed by attackers. Character arrays can be explicitly cleared
from memory after use.

**For convenience**: Use `String` passwords. Bruce provides convenient overloads
that accept String passwords and internally convert them to char arrays for you.

```java
// Maximum security approach with char arrays
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray());
PrivateKey key    = privateKey(keystore, "alias", "password".toCharArray());

// Convenience approach with Strings
KeyStore keystore = keystore("classpath:keystore.p12", "password");
PrivateKey key    = privateKey(keystore, "alias", "password");
```

## The `Bytes` Type

`Bytes` is the universal currency type for all Bruce cryptographic operations.
It is an immutable wrapper around a raw byte array that can be constructed from
and converted to a variety of representations on demand.

### Raw byte arrays

At the most basic level, computers work with bits. In Java, cryptographic
operations typically produce or consume arrays of bytes:

```java
Digester digester = digestBuilder().algorithm("SHA1").build();
Bytes hash = digester.digest(Bytes.from("message"));
byte[] rawBytes = hash.asBytes();
```

### Encodings

Raw byte arrays are not always a practical representation format — you cannot
directly use them in a text file, an email message or a JSON payload. Use
`Bytes` to encode the output:

```java
Digester digester = digestBuilder().algorithm("SHA1").build();
Bytes hash = digester.digest(Bytes.from("message"));

String base64 = hash.encode(BASE64); // "b5ua881ui4pzws3O03/p9ZIm4n0="
String hex    = hash.encode(HEX);
String url    = hash.encode(URL);    // URL-safe Base64
String mime   = hash.encode(MIME);   // line-broken Base64
```

Supported encodings are [Base64](https://en.wikipedia.org/wiki/Base64),
[Url](https://en.wikipedia.org/wiki/Percent-encoding),
[Mime](https://en.wikipedia.org/wiki/MIME),
[Hex](https://en.wikipedia.org/wiki/Hexadecimal).

To reconstruct `Bytes` from an encoded string, use
`Bytes.from(encoded, encoding)`:

```java
Bytes restored = Bytes.from("b5ua881ui4pzws3O03/p9ZIm4n0=", BASE64);
```

See the [`Bytes`](../api/bytes.md) page for the complete API.

## Providers

All builders support both `.provider(String)` and `.provider(Bruce.Provider)`.

```java
import static com.mirkocaserta.bruce.Bruce.Provider.*;

Digester digester = digestBuilder()
    .algorithm("SHA-1")
    .provider(BOUNCY_CASTLE)
    .build();
```

Built-in provider enum values are:

- `JCA` (default provider chain)
- `BOUNCY_CASTLE` (`BC`)
- `CONSCRYPT` (`Conscrypt`)

You can still use `.provider("...")` for custom provider names. Ensure the
provider jar is on the classpath before selecting it.

## Error Handling

There is a single exception in Bruce that wraps all kinds of errors: the
`BruceException`. As it is a `RuntimeException`, you are not forced to catch it.

Initialization and configuration errors are raised as soon as possible.

Wherever possible, the originating exception is wrapped and can be accessed
through the `getCause()` method.
