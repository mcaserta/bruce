# Cheat Sheet

This is a list of all available methods. Please refer to the detailed documentation for further info.

```java
// supported encodings
public enum Encoding { HEX, BASE64, URL, MIME };

// builder pattern methods (NEW - reduces parameter overload)
CipherBuilder cipherBuilder();
SignerBuilder signerBuilder();

// keystore methods
KeyStore keystore();
KeyStore keystore(String type);
KeyStore keystore(String location, char[] password);
KeyStore keystore(String location, char[] password, String type);
KeyStore keystore(String location, char[] password, String type, String provider);

// certificate methods
Certificate certificate(KeyStore keystore, String alias);

// key methods
PublicKey publicKey(KeyStore keystore, String alias);
PrivateKey privateKey(KeyStore keystore, String alias, char[] password);
Key secretKey(KeyStore keystore, String alias, char[] password);
KeyPair keyPair(String algorithm, int keySize);
KeyPair keyPair(String algorithm, String provider, int keySize);
KeyPair keyPair(String algorithm, int keySize, SecureRandom random);
KeyPair keyPair(String algorithm, String provider, int keySize, SecureRandom random);
byte[] symmetricKey(String algorithm);
byte[] symmetricKey(String algorithm, String provider);
String symmetricKey(String algorithm, Encoding encoding);
String symmetricKey(String algorithm, String provider, Encoding encoding);

// message digest methods
Digester digester(String algorithm, String provider);
Digester digester(String algorithm);
EncodingDigester digester(String algorithm, Encoding encoding);
EncodingDigester digester(String algorithm, Encoding encoding, Charset charset);
EncodingDigester digester(String algorithm, String provider, Encoding encoding);
EncodingDigester digester(String algorithm, String provider, Encoding encoding, Charset charset);

// signature methods
Signer signer(PrivateKey privateKey, String algorithm);
Signer signer(PrivateKey privateKey, String algorithm, String provider);
SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm);
SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider);
EncodingSigner signer(PrivateKey privateKey, String algorithm, Encoding encoding);
EncodingSigner signer(PrivateKey privateKey, String algorithm, Charset charset, Encoding encoding);
EncodingSigner signer(PrivateKey privateKey, String algorithm, String provider, Charset charset, Encoding encoding);

// verification methods
Verifier verifier(PublicKey publicKey, String algorithm);
Verifier verifier(PublicKey publicKey, String algorithm, String provider);
VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm);
VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, String provider);
EncodingVerifier verifier(PublicKey publicKey, String algorithm, Encoding encoding);
EncodingVerifier verifier(PublicKey publicKey, String algorithm, String provider, Encoding encoding);
EncodingVerifier verifier(PublicKey publicKey, String algorithm, String provider, Charset charset, Encoding encoding);

// symmetric ciphers
Cipher cipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, Mode mode);
Cipher cipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode);
EncodingCipher cipher(String key, String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset, Encoding encoding);
EncodingCipher cipher(String key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset, Encoding encoding);
CipherByKey cipher(String keyAlgorithm, String cipherAlgorithm, Mode mode);
CipherByKey cipher(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode);
EncodingCipherByKey cipherByKey(String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset);
EncodingCipherByKey cipherByKey(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset);

// asymmetric ciphers
Cipher cipher(Key key, String algorithm, Mode mode);
Cipher cipher(Key key, String algorithm, String provider, Mode mode);
EncodingCipher cipher(Key key, String algorithm, Mode mode, Encoding encoding, Charset charset);
EncodingCipher cipher(Key key, String algorithm, String provider, Mode mode, Encoding encoding, Charset charset);
CipherByKey cipher(Map<String, Key> keys, String algorithm);
CipherByKey cipher(Map<String, Key> keys, String algorithm, String provider);
EncodingCipherByKey cipher(Map<String, Key> keys, String algorithm, Encoding encoding, Charset charset);
EncodingCipherByKey cipher(Map<String, Key> keys, String algorithm, String provider, Encoding encoding, Charset charset);

// message authentication codes
Mac mac(Key key, String algorithm);
Mac mac(Key key, String algorithm, String provider);
EncodingMac mac(Key key, String algorithm, Encoding encoding, Charset charset);
EncodingMac mac(Key key, String algorithm, String provider, Encoding encoding, Charset charset);
```

## Builder Pattern Usage

For complex operations with many parameters, use the fluent builder APIs:

### Signer Builder

```java
// Simple signer
EncodingSigner signer = signerBuilder()
    .key(privateKey)
    .algorithm("SHA256withRSA")
    .build();

// Full configuration
EncodingSigner signer = signerBuilder()
    .key(privateKey)
    .algorithm("SHA256withRSA")
    .provider("BC")
    .charset(UTF_8)
    .encoding(BASE64)
    .build();

// Multi-key signer
EncodingSignerByKey signer = signerBuilder()
    .keys(privateKeyMap)
    .algorithm("SHA256withRSA")
    .encoding(BASE64)
    .buildByKey();
```

### Cipher Builder

```java
// Symmetric cipher
EncodingCipher cipher = cipherBuilder()
    .key("myKey")
    .keyAlgorithm("AES")
    .algorithm("AES/CBC/PKCS5Padding")
    .mode(ENCRYPT)
    .charset(UTF_8)
    .encoding(BASE64)
    .buildSymmetric();

// Asymmetric cipher
EncodingCipher cipher = cipherBuilder()
    .key(publicKey)
    .algorithm("RSA")
    .mode(ENCRYPT)
    .encoding(BASE64)
    .buildAsymmetric();
```

