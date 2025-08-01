# Symmetric Ciphers

## Cipher

```java
Cipher cipher(
    byte[] key, 
    String keyAlgorithm, 
    String cipherAlgorithm, 
    Mode mode
);
```

 Returns a symmetric cipher for the given key, key algorithm, cipher algorithm and mode.

### Usage Example

```java
Random rng = new SecureRandom();
byte[] iv = new byte[8];
rng.nextBytes(iv);
byte[] key = symmetricKey("DESede");
Cipher encrypter = Bruce.cipher(key, "DESede", "DESede/CBC/PKCS5Padding", ENCRYPT);
Cipher decrypter = Bruce.cipher(key, "DESede", "DESede/CBC/PKCS5Padding", DECRYPT);
byte[] clearText = "Hi there".getBytes(UTF_8);
byte[] cypherText = encrypter.encrypt(iv, clearText);
byte[] decryptedText = decrypter.encrypt(iv, cypherText);
assertArrayEquals(clearText, decryptedText);
```

## Builder Pattern Alternative

For complex symmetric cipher configurations, use the fluent builder API:

### Basic Symmetric Cipher Builder

```java
EncodingCipher cipher = cipherBuilder()
    .key("mySecretKey")
    .keyAlgorithm("AES")
    .algorithm("AES")
    .mode(ENCRYPT)
    .buildSymmetric();

String encrypted = cipher.encrypt("", "Hello World");
```

### Advanced Symmetric Cipher Builder

```java
EncodingCipher cipher = cipherBuilder()
    .key("mySecretKey")
    .keyAlgorithm("AES")
    .algorithm("AES/CBC/PKCS5Padding")
    .provider("BC")
    .mode(ENCRYPT)
    .charset(UTF_8)
    .encoding(BASE64)
    .buildSymmetric();

String encrypted = cipher.encrypt("myIV", "Hello World");
```

##   Cipher By Key

```java
CipherByKey cipher(
    String keyAlgorithm, 
    String cipherAlgorithm, 
    Mode mode
);
```

 Returns a cipher where the key can be passed at runtime through the returned interface.

### Usage Example

```java
Random rng = new SecureRandom();
byte[] iv = new byte[8]; // initialization vector
rng.nextBytes(iv);
byte[] key = symmetricKey("DESede");
CipherByKey encrypter = cipher("DESede", "DESede/CBC/PKCS5Padding", ENCRYPT);
CipherByKey decrypter = cipher("DESede", "DESede/CBC/PKCS5Padding", DECRYPT);
byte[] plainText = "Hi there".getBytes(UTF_8);
byte[] cypherText = encrypter.encrypt(key, iv, plainText);
byte[] decryptedText = decrypter.encrypt(key, iv, cypherText);
assertArrayEquals(plainText, decryptedText);
```

##  Encoding Cipher

```julia
EncodingCipher cipher(
    String key, 
    String keyAlgorithm, 
    String cipherAlgorithm, 
    Mode mode, 
    Charset charset, 
    Encoding encoding
);
```

 Returns an encoding cipher. The key must also be encoded with the specified encoding. The character set refers to the plain text message string encoding.

### Usage Example

```java
Random rng = new SecureRandom();
byte[] ivBA = new byte[8]; // initialization vector byte array
rng.nextBytes(ivBA);
String iv = Base64.getEncoder().encodeToString(ivBA);
String key = symmetricKey("DESede", BASE64);
EncodingCipher encrypter = cipher(key, "DESede", "DESede/CBC/PKCS5Padding", ENCRYPT, UTF_8, BASE64);
EncodingCipher decrypter = cipher(key, "DESede", "DESede/CBC/PKCS5Padding", DECRYPT, UTF_8, BASE64);
String plainText = "Hi there";
String cypherText = encrypter.encrypt(iv, plainText);
String decryptedText = decrypter.encrypt(iv, cypherText);
assertEquals(plainText, decryptedText);
```

## Encoding Cipher By Key

```java
EncodingCipherByKey cipherByKey(
    String keyAlgorithm, 
    String cipherAlgorithm, 
    Mode mode, 
    Charset charset
);
```

 Same as [encoding cipher](symmetric-ciphers.md#encoding-cipher) but allows you to provide the keys at runtime.

### Usage Example

```java
Random rng = new SecureRandom();
byte[] ivBA = new byte[8]; // initialization vector byte array
rng.nextBytes(ivBA);
String iv = Base64.getEncoder().encodeToString(ivBA);
String key = symmetricKey("DESede", BASE64);
EncodingCipherByKey encrypter = cipherByKey("DESede", "DESede/CBC/PKCS5Padding", ENCRYPT, UTF_8);
EncodingCipherByKey decrypter = cipherByKey("DESede", "DESede/CBC/PKCS5Padding", DECRYPT, UTF_8);
String clearText = "Hi there";
String cypherText = encrypter.encrypt(key, iv, clearText, BASE64);
String decryptedText = decrypter.encrypt(key, iv, cypherText, BASE64);
assertEquals(clearText, decryptedText);
```

