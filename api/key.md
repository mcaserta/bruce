# Keys

## Public Key

```java
PublicKey publicKey(
    KeyStore keystore, 
    String alias
);
```

 Loads a public key from a key store.

### Usage Example

```java
KeyStore keystore = keystore(
    "classpath:keystore.p12", 
    "password".toCharArray(), 
    "PKCS12"
);

PublicKey publicKey = publicKey(keystore, "alice");
```

##  Private Key

```java
PrivateKey privateKey(
    KeyStore keystore, 
    String alias, 
    char[] password
);
```

 Loads a public key from a key store. The password parameter is the private key's password.

### Usage Example

```java
KeyStore keystore = keystore(
    "classpath:keystore.p12", 
    "password".toCharArray(), 
    "PKCS12"
);

PrivateKey privateKey = 
    privateKey(keystore, "alice", "password".toCharArray());
```

##  Secret Key

```text
Key secretKey(
    KeyStore keystore, 
    String alias, 
    char[] password
);
```

 Loads a secret key from a key store. The password parameter is the secret key's password.

### Usage Example

```text
KeyStore keystore = keystore(
    "classpath:/keystore.p12", 
    "password".toCharArray(), 
    "PKCS12"
);

Key key = secretKey(keystore, "alice", "password".toCharArray());
```

## Symmetric Key

```java
byte[] symmetricKey(String algorithm);
```

 Generates a symmetric key using the given algorithm.

### Usage Example

```java
byte[] key = symmetricKey("DESede");
```

## Encoded Symmetric Key

```java
String symmetricKey(String algorithm, Encoding encoding);
```

 Generates a symmetric key using the given algorithm and encoding.

### Usage Example

```java
String key = symmetricKey("DESede", BASE64);
```

##  Key Pair

```java
KeyPair keyPair(String algorithm, int keySize);
```

 Generates a pair of keys for asymmetric cryptography.

### Usage Example

```java
KeyPair keyPair = keyPair("RSA", 4096);
Signer signer = signer(keyPair.getPrivate(), "SHA512withRSA");
Verifier verifier = verifier(keyPair.getPublic(), "SHA512withRSA");
byte[] signature = signer.sign(MESSAGE);
assertTrue(verifier.verify(MESSAGE, signature));
```

##  Key Pair with Custom PRNG

```java
KeyPair keyPair(
    String algorithm, 
    int keySize, 
    SecureRandom random
);
```

 Same as [key pair](key.md#key-pair) but allows passing a `SecureRandom` instance for custom initialization of the pseudo random number generator used when generating the keys.

### Usage Example

```java
SecureRandom random = SecureRandom.getInstanceStrong();
random.setSeed(new byte[]{0, 1, 2, 3, 4, 5});
KeyPair keyPair = keyPair("RSA", 4096, random);
Signer signer = signer(keyPair.getPrivate(), "SHA512withRSA");
Verifier verifier = verifier(keyPair.getPublic(), "SHA512withRSA");
byte[] signature = signer.sign(MESSAGE);
assertTrue(verifier.verify(MESSAGE, signature));
```

 

