# Asymmetric Ciphers

## Cipher

```java
Cipher cipher(Key key, String algorithm, Mode mode);
```

 Returns an asymmetric cipher.

### Usage Example

```java
KeyStore aliceKeystore = keystore("classpath:/keystore-alice.p12", "password".toCharArray(), "PKCS12");
KeyStore bobKeystore = keystore("classpath:/keystore-bob.p12", "password".toCharArray(), "PKCS12");
Key alicePrivateKey = privateKey(aliceKeystore, "alice", "password".toCharArray());
Key bobPrivateKey = privateKey(bobKeystore, "bob", "password".toCharArray());
Key alicePublicKey = publicKey(aliceKeystore, "alice");
Key bobPublicKey = publicKey(bobKeystore, "bob");

Cipher encryptForAlice = cipher(alicePublicKey, "RSA", ENCRYPT);
Cipher decryptForAlice = cipher(alicePrivateKey, "RSA", DECRYPT);
Cipher encryptForBob = cipher(bobPublicKey, "RSA", ENCRYPT);
Cipher decryptForBob = cipher(bobPrivateKey, "RSA", DECRYPT);

// Alice writes to Bob
byte[] aliceMsg01 = "Hello".getBytes(UTF_8);
byte[] aliceMsg01Encrypted = encryptForBob.encrypt(aliceMsg01);

// Bob decrypts Alice's message
byte[] aliceMsg01Decrypted = decryptForBob.encrypt(aliceMsg01Encrypted);

// Bob responds to Alice's message
byte[] bobMsg01 = "Hey Alice, nice to hear from you.".getBytes(UTF_8);
byte[] bobMsg01Encrypted = encryptForAlice.encrypt(bobMsg01);

// Alice decrypts Bob's message
byte[] bobMsg01Decrypted = decryptForAlice.encrypt(bobMsg01Encrypted);
```

##  Cipher By Key

```java
CipherByKey cipher(Map<String, Key> keys, String algorithm);
```

 Returns a cipher interface for working with a map of preconfigured keys.

### Usage Example

```java
KeyStore aliceKeystore = keystore("classpath:/keystore-alice.p12", "password".toCharArray(), "PKCS12");
KeyStore bobKeystore = keystore("classpath:/keystore-bob.p12", "password".toCharArray(), "PKCS12");
Key alicePrivateKey = privateKey(aliceKeystore, "alice", "password".toCharArray());
Key bobPrivateKey = privateKey(bobKeystore, "bob", "password".toCharArray());
Key alicePublicKey = publicKey(aliceKeystore, "alice");
Key bobPublicKey = publicKey(bobKeystore, "bob");

Map<String, Key> keys = Map.of(
        "alice-public", alicePublicKey,
        "alice-private", alicePrivateKey,
        "bob-public", bobPublicKey,
        "bob-private", bobPrivateKey
);

CipherByKey cipher = cipher(keys, "RSA");

// Alice writes to Bob
byte[] aliceMsg01 = "Hello".getBytes(UTF_8);
byte[] aliceMsg01Encrypted = cipher.encrypt("bob-public", ENCRYPT, aliceMsg01);

// Bob decrypts Alice's message
byte[] aliceMsg01Decrypted = cipher.encrypt("bob-private", DECRYPT, aliceMsg01Encrypted);
assertArrayEquals(aliceMsg01, aliceMsg01Decrypted);

// Bob responds to Alice's message
byte[] bobMsg01 = "Hey Alice, nice to hear from you.".getBytes(UTF_8);
byte[] bobMsg01Encrypted = cipher.encrypt("alice-public", ENCRYPT, bobMsg01);

// Alice decrypts Bob's message
byte[] bobMsg01Decrypted = cipher.encrypt("alice-private", DECRYPT, bobMsg01Encrypted);
assertArrayEquals(bobMsg01, bobMsg01Decrypted);
```

##  Encoding Cipher

```java
EncodingCipher cipher(
    Key key, 
    String algorithm, 
    Mode mode, 
    Encoding encoding, 
    Charset charset
);
```

 Returns an encoding cipher. The character set refers to the plain text message string encoding.

### Usage Example

```java
KeyStore aliceKeystore = keystore("classpath:/keystore-alice.p12", "password".toCharArray(), "PKCS12");
KeyStore bobKeystore = keystore("classpath:/keystore-bob.p12", "password".toCharArray(), "PKCS12");
Key alicePrivateKey = privateKey(aliceKeystore, "alice", "password".toCharArray());
Key bobPrivateKey = privateKey(bobKeystore, "bob", "password".toCharArray());
Key alicePublicKey = publicKey(aliceKeystore, "alice");
Key bobPublicKey = publicKey(bobKeystore, "bob");

EncodingCipher encryptForAlice = cipher(alicePublicKey, "RSA", ENCRYPT, BASE64, UTF_8);
EncodingCipher decryptForAlice = cipher(alicePrivateKey, "RSA", DECRYPT, BASE64, UTF_8);
EncodingCipher encryptForBob = cipher(bobPublicKey, "RSA", ENCRYPT, BASE64, UTF_8);
EncodingCipher decryptForBob = cipher(bobPrivateKey, "RSA", DECRYPT, BASE64, UTF_8);

// Alice writes to Bob
String aliceMsg01 = "Hello";
String aliceMsg01Encrypted = encryptForBob.encrypt(aliceMsg01);

// Bob decrypts Alice's message
String aliceMsg01Decrypted = decryptForBob.encrypt(aliceMsg01Encrypted);
assertEquals(aliceMsg01, aliceMsg01Decrypted);

// Bob responds to Alice's message
String bobMsg01 = "Hey Alice, nice to hear from you.";
String bobMsg01Encrypted = encryptForAlice.encrypt(bobMsg01);

// Alice decrypts Bob's message
String bobMsg01Decrypted = decryptForAlice.encrypt(bobMsg01Encrypted);
assertEquals(bobMsg01, bobMsg01Decrypted);
```

##  Encoding Cipher By Key

```java
EncodingCipherByKey cipher(
    Map<String, Key> keys, 
    String algorithm, 
    Encoding encoding, 
    Charset charset
);
```

 Returns an encoding cipher with a set of preconfigured keys.

### Usage Example

```java
KeyStore aliceKeystore = keystore("classpath:/keystore-alice.p12", "password".toCharArray(), "PKCS12");
KeyStore bobKeystore = keystore("classpath:/keystore-bob.p12", "password".toCharArray(), "PKCS12");
Key alicePrivateKey = privateKey(aliceKeystore, "alice", "password".toCharArray());
Key bobPrivateKey = privateKey(bobKeystore, "bob", "password".toCharArray());
Key alicePublicKey = publicKey(aliceKeystore, "alice");
Key bobPublicKey = publicKey(bobKeystore, "bob");

Map<String, Key> keys = Map.of(
    "alice-public", alicePublicKey,
    "alice-private", alicePrivateKey,
    "bob-public", bobPublicKey,
    "bob-private", bobPrivateKey
);

EncodingCipherByKey cipher = cipher(keys, "RSA", BASE64, UTF_8);

// Alice writes to Bob
String aliceMsg01 = "Hello";
String aliceMsg01Encrypted = cipher.encrypt("bob-public", ENCRYPT, aliceMsg01);

// Bob decrypts Alice's message
String aliceMsg01Decrypted = cipher.encrypt("bob-private", DECRYPT, aliceMsg01Encrypted);
assertEquals(aliceMsg01, aliceMsg01Decrypted);

// Bob responds to Alice's message
String bobMsg01 = "Hey Alice, nice to hear from you.";
String bobMsg01Encrypted = cipher.encrypt("alice-public", ENCRYPT, bobMsg01);

// Alice decrypts Bob's message
String bobMsg01Decrypted = cipher.encrypt("alice-private", DECRYPT, bobMsg01Encrypted);
assertEquals(bobMsg01, bobMsg01Decrypted);
```

