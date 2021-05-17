# Cheat Sheet

This is a list of all available methods. Please refer to the detailed documentation for further info.

```java
// supported encodings
public enum Encoding { HEX, BASE64, URL, MIME };

// keystore methods
KeyStore keystore();
KeyStore keystore(String type);
KeyStore keystore(String location, String password);
KeyStore keystore(String location, String password, String type);
KeyStore keystore(String location, String password, String type, String provider);

// certificate methods
Certificate certificate(KeyStore keystore, String alias);

// key methods
PublicKey publicKey(KeyStore keystore, String alias);
PrivateKey privateKey(KeyStore keystore, String alias, String password);
Key secretKey(KeyStore keystore, String alias, String password);
byte[] symmetricKey(String algorithm);
byte[] symmetricKey(String algorithm, String provider);
String symmetricKey(String algorithm, Encoding encoding);
String symmetricKey(String algorithm, String provider, Encoding encoding);

// message digest methods
Digester digester(String algorithm, String provider);
Digester digester(String algorithm);
EncodingDigester digester(String algorithm, Encoding encoding);
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

