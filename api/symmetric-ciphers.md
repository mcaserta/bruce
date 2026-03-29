# Symmetric Ciphers

All symmetric cipher instances are created via `cipherBuilder()` (static import
from `Bruce`). Input and output use the [`Bytes`](bytes.md) universal type.

## Encryptor

Returns a `SymmetricEncryptor` that encrypts messages with a fixed symmetric
key.

### Usage examples

```java
// Generate a key and IV
byte[] keyBytes = symmetricKey("AES");
byte[] ivBytes  = new byte[16];
new SecureRandom().nextBytes(ivBytes);

SymmetricEncryptor encryptor = cipherBuilder()
    .key(keyBytes)
    .keyAlgorithm("AES")
    .algorithm("AES/CBC/PKCS5Padding")
    .buildSymmetricEncryptor();

Bytes iv         = Bytes.from(ivBytes);
Bytes ciphertext = encryptor.encrypt(iv, Bytes.from("Hello World"));

// serialize to BASE64 for transport
String ivB64  = iv.encode(BASE64);
String encB64 = ciphertext.encode(BASE64);
```

### Builder options

```java
import static com.mirkocaserta.bruce.Bruce.Provider.*;
import static com.mirkocaserta.bruce.Bruce.SymmetricKeyAlgorithm.*;
import static com.mirkocaserta.bruce.Bruce.CipherAlgorithm.*;

// String-based algorithms (open-ended, supports any JCA algorithm)
SymmetricEncryptor encryptor = cipherBuilder()
    .key(keyBytes)               // raw byte[] or Bytes
    .keyAlgorithm(AES)
    .algorithm(AES_CBC_PKCS5PADDING)
    .provider(BOUNCY_CASTLE)      // optional, defaults to JCA
    // .provider("BC")            // string-based alternative
    .buildSymmetricEncryptor();

// Enum-based algorithms (type-safe, IDE auto-completion)
SymmetricEncryptor encryptor2 = cipherBuilder()
    .key(keyBytes)
    .algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_CBC_PKCS5)
    .provider(BOUNCY_CASTLE)      // optional
    .buildSymmetricEncryptor();
```

Common `SymmetricAlgorithm` key constants: `AES`, `DES`, `DESEDE`, `BLOWFISH`.

Common `SymmetricCipherAlgorithm` transformation constants: `AES_CBC_PKCS5`,
`AES_CBC_NO_PADDING`, `AES_GCM_NO_PADDING`, `AES_CTR_NO_PADDING`,
`AES_ECB_PKCS5`, `DES_CBC_PKCS5`, `DESEDE_CBC_PKCS5`.

---

## Decryptor

Returns a `SymmetricDecryptor` that decrypts messages with a fixed symmetric
key.

### Usage examples

```java
SymmetricDecryptor decryptor = cipherBuilder()
    .key(keyBytes)
    .keyAlgorithm("AES")
    .algorithm("AES/CBC/PKCS5Padding")
    .buildSymmetricDecryptor();

// raw bytes → Bytes
Bytes plaintext = decryptor.decrypt(iv, ciphertext);
String text     = plaintext.asString();   // UTF-8

// BASE64 strings → String
Bytes ivFromB64  = Bytes.from(ivB64, BASE64);
Bytes encFromB64 = Bytes.from(encB64, BASE64);
String decrypted = decryptor.decrypt(ivFromB64, encFromB64).asString();
```

---

## Full round-trip

```java
byte[] keyBytes = symmetricKey("DESede");
SymmetricEncryptor enc = cipherBuilder()
    .key(keyBytes).keyAlgorithm("DESede").algorithm("DESede/CBC/PKCS5Padding")
    .buildSymmetricEncryptor();
SymmetricDecryptor dec = cipherBuilder()
    .key(keyBytes).keyAlgorithm("DESede").algorithm("DESede/CBC/PKCS5Padding")
    .buildSymmetricDecryptor();

byte[] rawIv    = new byte[8];
new SecureRandom().nextBytes(rawIv);
Bytes iv        = Bytes.from(rawIv);

Bytes clearText    = Bytes.from("Hi there");
Bytes cipherText   = enc.encrypt(iv, clearText);
Bytes decryptedText = dec.decrypt(iv, cipherText);
assertEquals(clearText, decryptedText);
```

---

## Encryptor / Decryptor by Key

For use-cases where the key is supplied at call time (e.g., per-user keys):

```java
SymmetricEncryptorByKey encByKey = cipherBuilder()
    .keyAlgorithm("AES")
    .algorithm("AES/CBC/PKCS5Padding")
    .buildSymmetricEncryptorByKey();

SymmetricDecryptorByKey decByKey = cipherBuilder()
    .keyAlgorithm("AES")
    .algorithm("AES/CBC/PKCS5Padding")
    .buildSymmetricDecryptorByKey();

Bytes key        = Bytes.from(keyBytes);
Bytes iv         = Bytes.from(ivBytes);
Bytes ciphertext = encByKey.encrypt(key, iv, Bytes.from("Hello World"));
Bytes plaintext  = decByKey.decrypt(key, iv, ciphertext);
```

### Interfaces

```java
@FunctionalInterface
public interface SymmetricEncryptor {
    Bytes encrypt(Bytes iv, Bytes plaintext);
}

@FunctionalInterface
public interface SymmetricDecryptor {
    Bytes decrypt(Bytes iv, Bytes ciphertext);
}

@FunctionalInterface
public interface SymmetricEncryptorByKey {
    Bytes encrypt(Bytes key, Bytes iv, Bytes plaintext);
}

@FunctionalInterface
public interface SymmetricDecryptorByKey {
    Bytes decrypt(Bytes key, Bytes iv, Bytes ciphertext);
}
```
