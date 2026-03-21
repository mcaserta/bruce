# Asymmetric Ciphers

All asymmetric cipher instances are created via `cipherBuilder()` (static import
from `Bruce`). Input and output use the [`Bytes`](bytes.md) universal type.

## Encryptor

Returns an `AsymmetricEncryptor` that encrypts messages with an asymmetric
public key.

### Usage examples

```java
KeyStore bobKeystore = keystore("classpath:/keystore-bob.p12", "password".toCharArray(), "PKCS12");
PublicKey bobPublicKey = publicKey(bobKeystore, "bob");

AsymmetricEncryptor encryptor = cipherBuilder()
    .key(bobPublicKey)
    .algorithm("RSA")
    .buildAsymmetricEncryptor();

// raw bytes → Bytes
Bytes encrypted = encryptor.encrypt(Bytes.from("Hello Bob".getBytes(UTF_8)));

// UTF-8 text → BASE64 string
String enc64 = encryptor.encrypt(Bytes.from("Hello Bob")).encode(BASE64);

// UTF-8 text → HEX string
String encHex = encryptor.encrypt(Bytes.from("Hello Bob")).encode(HEX);
```

### Builder options

```java
AsymmetricEncryptor encryptor = cipherBuilder()
    .key(publicKey)
    .algorithm("RSA")
    .provider("BC")          // optional
    .buildAsymmetricEncryptor();
```

---

## Decryptor

Returns an `AsymmetricDecryptor` that decrypts messages with an asymmetric
private key.

### Usage examples

```java
KeyStore bobKeystore = keystore("classpath:/keystore-bob.p12", "password".toCharArray(), "PKCS12");
PrivateKey bobPrivateKey = privateKey(bobKeystore, "bob", "password".toCharArray());

AsymmetricDecryptor decryptor = cipherBuilder()
    .key(bobPrivateKey)
    .algorithm("RSA")
    .buildAsymmetricDecryptor();

// Bytes → Bytes
Bytes plain = decryptor.decrypt(encrypted);
String text = plain.asString();

// BASE64 string → String
String plain2 = decryptor.decrypt(Bytes.from(enc64, BASE64)).asString();

// HEX string → String
String plain3 = decryptor.decrypt(Bytes.from(encHex, HEX)).asString();
```

---

## Full Alice ↔ Bob round-trip

```java
KeyStore aliceKs = keystore("classpath:/keystore-alice.p12", "password".toCharArray(), "PKCS12");
KeyStore bobKs   = keystore("classpath:/keystore-bob.p12",   "password".toCharArray(), "PKCS12");

AsymmetricEncryptor encryptForBob   = cipherBuilder().key(publicKey(bobKs, "bob")).algorithm("RSA").buildAsymmetricEncryptor();
AsymmetricDecryptor decryptAsBob    = cipherBuilder().key(privateKey(bobKs, "bob", "password".toCharArray())).algorithm("RSA").buildAsymmetricDecryptor();
AsymmetricEncryptor encryptForAlice = cipherBuilder().key(publicKey(aliceKs, "alice")).algorithm("RSA").buildAsymmetricEncryptor();
AsymmetricDecryptor decryptAsAlice  = cipherBuilder().key(privateKey(aliceKs, "alice", "password".toCharArray())).algorithm("RSA").buildAsymmetricDecryptor();

// Alice → Bob (raw bytes)
Bytes aliceMsg  = Bytes.from("Hello Bob");
Bytes encrypted = encryptForBob.encrypt(aliceMsg);
Bytes decrypted = decryptAsBob.decrypt(encrypted);
assertEquals(aliceMsg, decrypted);

// Bob → Alice (via BASE64 strings)
String bobMsg  = "Hey Alice!";
String enc64   = encryptForAlice.encrypt(Bytes.from(bobMsg)).encode(BASE64);
String dec64   = decryptAsAlice.decrypt(Bytes.from(enc64, BASE64)).asString();
assertEquals(bobMsg, dec64);
```

---

## Encryptor / Decryptor by Key

For runtime key selection:

```java
Map<String, Key> pubKeys  = Map.of("alice", alicePub, "bob", bobPub);
Map<String, Key> privKeys = Map.of("alice", alicePriv, "bob", bobPriv);

AsymmetricEncryptorByKey encryptors = cipherBuilder().keys(pubKeys).algorithm("RSA").buildAsymmetricEncryptorByKey();
AsymmetricDecryptorByKey decryptors = cipherBuilder().keys(privKeys).algorithm("RSA").buildAsymmetricDecryptorByKey();

Bytes enc = encryptors.encrypt("bob", Bytes.from("Hello Bob"));
Bytes dec = decryptors.decrypt("bob", enc);
```

### Interfaces

```java
@FunctionalInterface
public interface AsymmetricEncryptor {
    Bytes encrypt(Bytes plaintext);
}

@FunctionalInterface
public interface AsymmetricDecryptor {
    Bytes decrypt(Bytes ciphertext);
}

@FunctionalInterface
public interface AsymmetricEncryptorByKey {
    Bytes encrypt(String keyId, Bytes plaintext);
}

@FunctionalInterface
public interface AsymmetricDecryptorByKey {
    Bytes decrypt(String keyId, Bytes ciphertext);
}
```
