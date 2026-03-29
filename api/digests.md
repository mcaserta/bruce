# Digests

## Digester

Returns a `Digester` for the given algorithm. All input and output use the
[`Bytes`](bytes.md) universal type.

### Usage examples

```java
// Build once
Digester digester = digestBuilder().algorithm("SHA-256").build();

// raw bytes → Bytes
Bytes raw = digester.digest(Bytes.from("hello".getBytes(UTF_8)));

// UTF-8 text → BASE64 string
String b64 = digester.digest(Bytes.from("hello")).encode(BASE64);

// UTF-8 text → HEX string
String hex = digester.digest(Bytes.from("hello")).encode(HEX);

// explicit charset → BASE64 string
String b64_2 = digester.digest(Bytes.from("hello 👋🏻", UTF_16)).encode(BASE64);

// file path → BASE64 string (streaming, no full file load)
String fileHash = digester.digest(Path.of("src/test/resources/test-file-1"))
                          .encode(BASE64);

// java.io.File → HEX string (delegates to digest(Path), same streaming behavior)
String fileHex = digester.digest(new File("src/test/resources/test-file-1"))
                         .encode(HEX);
```

### Builder options

```java
import static com.mirkocaserta.bruce.Bruce.Provider.*;

// String-based algorithm (open-ended, supports any JCA algorithm)
Digester digester = digestBuilder()
    .algorithm("SHA-256")
    .provider(BOUNCY_CASTLE)  // optional, defaults to JCA
    // .provider("BC")        // string-based alternative
    .build();

// Enum-based algorithm (type-safe, IDE auto-completion)
Digester digester2 = digestBuilder()
    .algorithm(DigestAlgorithm.SHA_256)
    .provider(BOUNCY_CASTLE)  // optional
    .build();
```

Available `DigestAlgorithm` constants: `MD5`, `SHA_1`, `SHA_224`, `SHA_256`,
`SHA_384`, `SHA_512`, `SHA_512_224`, `SHA_512_256`, `SHA3_224`, `SHA3_256`,
`SHA3_384`, `SHA3_512`.

### Interface

```java
public interface Digester {
    Bytes digest(Bytes input);
    Bytes digest(Path file);                // streaming file read
    default Bytes digest(File file) { ... } // delegates to digest(Path)
}
```

### Input / output combinations

| Input          | How to construct                   | Consume output                                     |
| -------------- | ---------------------------------- | -------------------------------------------------- |
| raw `byte[]`   | `Bytes.from(rawBytes)`             | `.asBytes()`                                       |
| UTF-8 text     | `Bytes.from("text")`               | `.encode(HEX)` / `.encode(BASE64)` / `.asString()` |
| custom charset | `Bytes.from("text", charset)`      | `.encode(...)`                                     |
| encoded string | `Bytes.from("abc…", Encoding.HEX)` | `.encode(...)`                                     |
| file           | pass `Path` / `File` directly      | `.encode(...)`                                     |
