# Cheat Sheet

Complete list of available builder methods and functional interfaces.

- Keystore / key helpers → static imports from
  `com.mirkocaserta.bruce.Keystores`
- Builder factories → static imports from `com.mirkocaserta.bruce.Bruce`
- Encoding constants → static imports from
  `com.mirkocaserta.bruce.Bruce.Encoding`
- Universal I/O type → `com.mirkocaserta.bruce.Bytes`

```java
// ─── Encoding enum (Bruce.Encoding) ─────────────────────────────────────────
public enum Encoding { HEX, BASE64, URL, MIME }

// ─── Provider enum (Bruce.Provider) ─────────────────────────────────────────
public enum Provider { JCA, BOUNCY_CASTLE, CONSCRYPT }

// ─── Algorithm enums (AlgorithmId) ──────────────────────────────────────────
// All implement AlgorithmId: String algorithmName()

DigestAlgorithm          // MD5, SHA_1, SHA_224, SHA_256, SHA_384, SHA_512,
                         // SHA_512_224, SHA_512_256,
                         // SHA3_224, SHA3_256, SHA3_384, SHA3_512

MacAlgorithm             // HMAC_MD5, HMAC_SHA_1, HMAC_SHA_224, HMAC_SHA_256,
                         // HMAC_SHA_384, HMAC_SHA_512, HMAC_SHA_512_224,
                         // HMAC_SHA_512_256,
                         // HMAC_SHA3_224, HMAC_SHA3_256, HMAC_SHA3_384, HMAC_SHA3_512

SignatureAlgorithm       // *_WITH_RSA, *_WITH_DSA, *_WITH_ECDSA, RSASSA_PSS
                         // (MD5, SHA1, SHA224, SHA256, SHA384, SHA512,
                         //  SHA512_224, SHA512_256, SHA3_256, SHA3_384, SHA3_512)

SymmetricAlgorithm       // AES, DES, DESEDE, BLOWFISH, RC2, RC4, CHACHA20

SymmetricCipherAlgorithm // AES_CBC_PKCS5, AES_CBC_NO_PADDING, AES_CTR_NO_PADDING,
                         // AES_ECB_PKCS5, AES_ECB_NO_PADDING, AES_GCM_NO_PADDING,
                         // DES_CBC_PKCS5, DES_ECB_PKCS5,
                         // DESEDE_CBC_PKCS5, DESEDE_ECB_PKCS5,
                         // BLOWFISH_CBC_PKCS5, BLOWFISH_ECB_PKCS5

AsymmetricAlgorithm      // RSA, RSA_ECB_PKCS1, RSA_ECB_OAEP_SHA1_MGF1,
                         // RSA_ECB_OAEP_SHA256_MGF1, RSA_ECB_OAEP_SHA384_MGF1,
                         // RSA_ECB_OAEP_SHA512_MGF1, RSA_ECB_NO_PADDING

// ─── Bytes ───────────────────────────────────────────────────────────────────
// Construction
Bytes.from(byte[]);
Bytes.from(String);                         // UTF-8
Bytes.from(String, Charset);
Bytes.from(String, Encoding);               // decode encoded string
Bytes.from(Path);
Bytes.from(File);
Bytes.from(InputStream);
Bytes.fromPem(String);

// Consumption
byte[]  b.asBytes();
String  b.encode(Encoding);
String  b.toPem(PemType type);              // e.g. PemType.CERTIFICATE
String  b.asString();                       // UTF-8
String  b.asString(Charset);
int     b.length();
boolean b.isEmpty();

// ─── Keystore (com.mirkocaserta.bruce.Keystores) ─────────────────────────────
KeyStore keystore();
KeyStore keystore(String type);
KeyStore keystore(String location, char[] password);
KeyStore keystore(String location, String password);
KeyStore keystore(String location, char[] password, String type);
KeyStore keystore(String location, String password, String type);
KeyStore keystore(String location, char[] password, String type, String provider);
KeyStore keystore(String location, char[] password, String type, Provider provider);
KeyStore keystore(String location, String password, String type, String provider);
KeyStore keystore(String location, String password, String type, Provider provider);
byte[]   keystoreToBytes(KeyStore keystore, char[] password);
byte[]   keystoreToBytes(KeyStore keystore, String password);
String   keystoreToString(KeyStore keystore, char[] password, Encoding encoding);
String   keystoreToString(KeyStore keystore, String password, Encoding encoding);
void     keystoreToFile(KeyStore keystore, char[] password, Path path);
void     keystoreToFile(KeyStore keystore, String password, Path path);
void     keystoreToFile(KeyStore keystore, char[] password, File file);
void     keystoreToFile(KeyStore keystore, String password, File file);

// ─── Certificates (com.mirkocaserta.bruce.Keystores) ─────────────────────────
Certificate certificate(KeyStore keystore, String alias);
Certificate certificateFromPem(String pem);
Certificate certificateFromDer(byte[] der);
String      certificateToPem(Certificate certificate);
byte[]      certificateToDer(Certificate certificate);

// ─── Keys (com.mirkocaserta.bruce.Keystores) ─────────────────────────────────
PublicKey  publicKey(KeyStore keystore, String alias);
PrivateKey privateKey(KeyStore keystore, String alias, char[] password);
PrivateKey privateKey(KeyStore keystore, String alias, String password);
Key        secretKey(KeyStore keystore, String alias, char[] password);
Key        secretKey(KeyStore keystore, String alias, String password);
PrivateKey privateKeyFromPem(String pem, String algorithm);
PublicKey  publicKeyFromPem(String pem, String algorithm);
PrivateKey privateKeyFromDer(byte[] der, String algorithm);
PublicKey  publicKeyFromDer(byte[] der, String algorithm);
String     keyToPem(Key key);
byte[]     keyToDer(Key key);
byte[]     pemToDer(String pem);
String     derToPem(byte[] der, PemType type);
PrivateKey rsaPrivateKeyFromPkcs1(byte[] pkcs1Der);
PrivateKey rsaPrivateKeyFromPkcs1Pem(String pem);
byte[]     rsaPrivateKeyToPkcs1(PrivateKey privateKey);
String     rsaPrivateKeyToPkcs1Pem(PrivateKey privateKey);
PublicKey  rsaPublicKeyFromPkcs1(byte[] pkcs1Der);
PublicKey  rsaPublicKeyFromPkcs1Pem(String pem);
byte[]     rsaPublicKeyToPkcs1(PublicKey publicKey);
String     rsaPublicKeyToPkcs1Pem(PublicKey publicKey);
KeyPair    keyPair(String algorithm, int keySize);
KeyPair    keyPair(String algorithm, String provider, int keySize);
KeyPair    keyPair(String algorithm, Provider provider, int keySize);
KeyPair    keyPair(String algorithm, int keySize, SecureRandom random);
KeyPair    keyPair(String algorithm, String provider, int keySize, SecureRandom random);
KeyPair    keyPair(String algorithm, Provider provider, int keySize, SecureRandom random);
byte[]     symmetricKey(String algorithm);
byte[]     symmetricKey(String algorithm, String provider);
byte[]     symmetricKey(String algorithm, Provider provider);
String     symmetricKey(String algorithm, Encoding encoding);
String     symmetricKey(String algorithm, String provider, Encoding encoding);
String     symmetricKey(String algorithm, Provider provider, Encoding encoding);

// ─── Digests (Bruce.digestBuilder) ──────────────────────────────────────────
DigestBuilder digestBuilder()
  .algorithm(String)           // e.g. "SHA-256"
  .algorithm(DigestAlgorithm)  // type-safe alternative
  .provider(String)            // optional
  .provider(Provider)          // optional
  .build()                     // → Digester

// Digester interface
Bytes  Digester.digest(Bytes input)
Bytes  Digester.digest(Path file)     // streaming
Bytes  Digester.digest(File file)     // delegates to Path variant

// ─── Signatures (Bruce.signerBuilder / verifierBuilder) ─────────────────────
SignerBuilder signerBuilder()
  .key(PrivateKey)                    // single key
  .keys(Map<String, PrivateKey>)      // multi-key
  .algorithm(String)                  // e.g. "SHA256withRSA"
  .algorithm(SignatureAlgorithm)      // type-safe alternative
  .provider(String)                   // optional
  .provider(Provider)                 // optional
  .build()                            // → Signer
  .buildByKey()                       // → SignerByKey

VerifierBuilder verifierBuilder()
  .key(PublicKey)                     // single key
  .keys(Map<String, PublicKey>)       // multi-key
  .algorithm(String)                  // e.g. "SHA256withRSA"
  .algorithm(SignatureAlgorithm)      // type-safe alternative
  .provider(String)                   // optional
  .provider(Provider)                 // optional
  .build()                            // → Verifier
  .buildByKey()                       // → VerifierByKey

// Signer / SignerByKey interfaces
Bytes  Signer.sign(Bytes message)
Bytes  SignerByKey.sign(String keyId, Bytes message)

// Verifier / VerifierByKey interfaces
boolean  Verifier.verify(Bytes message, Bytes signature)
boolean  VerifierByKey.verify(String keyId, Bytes message, Bytes signature)

// ─── Ciphers (Bruce.cipherBuilder) ──────────────────────────────────────────
CipherBuilder cipherBuilder()
  // symmetric fixed-key
  .key(byte[])                        // raw bytes
  .key(Bytes)                         // or Bytes
  .keyAlgorithm(String)               // e.g. "AES"
  .keyAlgorithm(SymmetricAlgorithm)   // type-safe alternative
  .algorithm(String)                  // e.g. "AES/CBC/PKCS5Padding"
  .algorithm(SymmetricCipherAlgorithm) // type-safe alternative
  .algorithms(String, String)         // convenience: keyAlgo + cipherAlgo
  .algorithms(SymmetricAlgorithm, SymmetricCipherAlgorithm) // type-safe convenience
  .provider(String)                   // optional
  .provider(Provider)                 // optional
  .buildSymmetricEncryptor()          // → SymmetricEncryptor
  .buildSymmetricDecryptor()          // → SymmetricDecryptor
  .buildSymmetricEncryptorByKey()     // → SymmetricEncryptorByKey (no fixed key)
  .buildSymmetricDecryptorByKey()     // → SymmetricDecryptorByKey

  // asymmetric fixed-key
  .key(Key)                           // PublicKey or PrivateKey
  .algorithm(String)                  // e.g. "RSA/ECB/PKCS1Padding"
  .algorithm(AsymmetricAlgorithm)     // type-safe alternative
  .provider(String)                   // optional
  .provider(Provider)                 // optional
  .buildAsymmetricEncryptor()         // → AsymmetricEncryptor
  .buildAsymmetricDecryptor()         // → AsymmetricDecryptor

  // asymmetric by-key
  .keys(Map<String, Key>)
  .buildAsymmetricEncryptorByKey()    // → AsymmetricEncryptorByKey
  .buildAsymmetricDecryptorByKey()    // → AsymmetricDecryptorByKey

// Symmetric interfaces
Bytes  SymmetricEncryptor.encrypt(Bytes iv, Bytes plaintext)
Bytes  SymmetricDecryptor.decrypt(Bytes iv, Bytes ciphertext)
Bytes  SymmetricEncryptorByKey.encrypt(Bytes key, Bytes iv, Bytes plaintext)
Bytes  SymmetricDecryptorByKey.decrypt(Bytes key, Bytes iv, Bytes ciphertext)

// Asymmetric interfaces
Bytes  AsymmetricEncryptor.encrypt(Bytes plaintext)
Bytes  AsymmetricDecryptor.decrypt(Bytes ciphertext)
Bytes  AsymmetricEncryptorByKey.encrypt(String keyId, Bytes plaintext)
Bytes  AsymmetricDecryptorByKey.decrypt(String keyId, Bytes ciphertext)

// ─── Message Authentication Codes (Bruce.macBuilder) ─────────────────────────
MacBuilder macBuilder()
  .key(Key)
  .algorithm(String)                 // e.g. "HmacSHA256"
  .algorithm(MacAlgorithm)           // type-safe alternative
  .provider(String)                  // optional
  .provider(Provider)                // optional
  .build()                           // → Mac

// Mac interface
Bytes  Mac.get(Bytes message)
```
