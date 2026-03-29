# Keys

All methods below are available as static imports from
`com.mirkocaserta.bruce.Keystores`.

## Public Key

```java
PublicKey publicKey(KeyStore keystore, String alias);
```

Loads a public key from a key store.

### Usage Example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");

PublicKey publicKey = publicKey(keystore, "alice");
```

## Private Key

```java
PrivateKey privateKey(KeyStore keystore, String alias, char[] password);
PrivateKey privateKey(KeyStore keystore, String alias, String password);
```

Loads a private key from a key store. The password parameter is the private
key's password.

### Usage Example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");

PrivateKey privateKey = privateKey(keystore, "alice", "password".toCharArray());
// or with String convenience overload:
PrivateKey privateKey = privateKey(keystore, "alice", "password");
```

## Secret Key

```java
Key secretKey(KeyStore keystore, String alias, char[] password);
Key secretKey(KeyStore keystore, String alias, String password);
```

Loads a secret key from a key store. The password parameter is the secret key's
password.

### Usage Example

```java
KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");

Key key = secretKey(keystore, "hmac", "password".toCharArray());
// or with String convenience overload:
Key key = secretKey(keystore, "hmac", "password");
```

## Symmetric Key

```java
byte[]  symmetricKey(String algorithm);
byte[]  symmetricKey(SymmetricKeyAlgorithm algorithm);
byte[]  symmetricKey(String algorithm, String provider);
byte[]  symmetricKey(SymmetricKeyAlgorithm algorithm, String provider);
byte[]  symmetricKey(String algorithm, Provider provider);
byte[]  symmetricKey(SymmetricKeyAlgorithm algorithm, Provider provider);
String  symmetricKey(String algorithm, Encoding encoding);
String  symmetricKey(SymmetricKeyAlgorithm algorithm, Encoding encoding);
String  symmetricKey(String algorithm, String provider, Encoding encoding);
String  symmetricKey(SymmetricKeyAlgorithm algorithm, String provider, Encoding encoding);
String  symmetricKey(String algorithm, Provider provider, Encoding encoding);
String  symmetricKey(SymmetricKeyAlgorithm algorithm, Provider provider, Encoding encoding);
```

Generates a random symmetric key using the given algorithm.

### Usage Examples

```java
// generate raw bytes
byte[] rawKey = symmetricKey(SymmetricKeyAlgorithm.AES);

// generate BASE64-encoded key string
String b64Key = symmetricKey(SymmetricKeyAlgorithm.AES, BASE64);

// use key as Bytes for the CipherBuilder
Bytes key = Bytes.from(b64Key, BASE64);
```

## Key Pair

```java
KeyPair keyPair(String algorithm, int keySize);
KeyPair keyPair(AsymmetricKeyAlgorithm algorithm, int keySize);
KeyPair keyPair(String algorithm, String provider, int keySize);
KeyPair keyPair(AsymmetricKeyAlgorithm algorithm, String provider, int keySize);
KeyPair keyPair(String algorithm, Provider provider, int keySize);
KeyPair keyPair(AsymmetricKeyAlgorithm algorithm, Provider provider, int keySize);
```

Generates a pair of keys for asymmetric cryptography.

### Usage Example

```java
KeyPair keyPair = keyPair(AsymmetricKeyAlgorithm.RSA, 4096);

Signer signer   = signerBuilder().key(keyPair.getPrivate()).algorithm("SHA512withRSA").build();
Verifier verifier = verifierBuilder().key(keyPair.getPublic()).algorithm("SHA512withRSA").build();

Bytes message   = Bytes.from("Hello");
Bytes signature = signer.sign(message);
assertTrue(verifier.verify(message, signature));
```

## Key Pair with Custom PRNG

```java
KeyPair keyPair(String algorithm, int keySize, SecureRandom random);
KeyPair keyPair(AsymmetricKeyAlgorithm algorithm, int keySize, SecureRandom random);
KeyPair keyPair(String algorithm, String provider, int keySize, SecureRandom random);
KeyPair keyPair(AsymmetricKeyAlgorithm algorithm, String provider, int keySize, SecureRandom random);
KeyPair keyPair(String algorithm, Provider provider, int keySize, SecureRandom random);
KeyPair keyPair(AsymmetricKeyAlgorithm algorithm, Provider provider, int keySize, SecureRandom random);
```

Same as [key pair](#key-pair) but allows passing a `SecureRandom` instance for
custom initialization of the pseudo random number generator.

### Usage Example

```java
SecureRandom random = SecureRandom.getInstanceStrong();
random.setSeed(new byte[]{0, 1, 2, 3, 4, 5});
KeyPair keyPair = keyPair(AsymmetricKeyAlgorithm.RSA, 4096, random);
```

## Key Format Conversions (PEM / DER / PKCS#1)

Bruce supports key format conversions without Bouncy Castle.

```java
// Generic key PEM/DER exports
String keyToPem(Key key);
byte[] keyToDer(Key key);

// PKCS#8 PEM/DER -> key
PrivateKey privateKeyFromPem(String pem, String algorithm);
PublicKey publicKeyFromPem(String pem, String algorithm);
PrivateKey privateKeyFromDer(byte[] der, String algorithm);
PublicKey publicKeyFromDer(byte[] der, String algorithm);

// Generic PEM <-> DER helpers
byte[] pemToDer(String pem);
String derToPem(byte[] der, PemType type);

// RSA PKCS#1 support
PrivateKey rsaPrivateKeyFromPkcs1(byte[] pkcs1Der);
PrivateKey rsaPrivateKeyFromPkcs1Pem(String pem);
byte[] rsaPrivateKeyToPkcs1(PrivateKey privateKey);
String rsaPrivateKeyToPkcs1Pem(PrivateKey privateKey);

PublicKey rsaPublicKeyFromPkcs1(byte[] pkcs1Der);
PublicKey rsaPublicKeyFromPkcs1Pem(String pem);
byte[] rsaPublicKeyToPkcs1(PublicKey publicKey);
String rsaPublicKeyToPkcs1Pem(PublicKey publicKey);
```

### Usage Example

```java
KeyPair kp = keyPair("RSA", 2048);

// PKCS#8 / SPKI PEM
String privatePem = keyToPem(kp.getPrivate());
String publicPem  = keyToPem(kp.getPublic());

PrivateKey privateFromPem = privateKeyFromPem(privatePem, "RSA");
PublicKey publicFromPem   = publicKeyFromPem(publicPem, "RSA");

// RSA PKCS#1
String rsaPrivatePkcs1Pem = rsaPrivateKeyToPkcs1Pem(kp.getPrivate());
String rsaPublicPkcs1Pem  = rsaPublicKeyToPkcs1Pem(kp.getPublic());

PrivateKey rsaPrivateRestored = rsaPrivateKeyFromPkcs1Pem(rsaPrivatePkcs1Pem);
PublicKey rsaPublicRestored   = rsaPublicKeyFromPkcs1Pem(rsaPublicPkcs1Pem);
```
