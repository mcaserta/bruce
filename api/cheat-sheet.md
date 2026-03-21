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

// ─── Bytes ───────────────────────────────────────────────────────────────────
// Construction
Bytes.from(byte[]);
Bytes.from(String);                         // UTF-8
Bytes.from(String, Charset);
Bytes.from(String, Encoding);               // decode encoded string
Bytes.fromFile(Path);
Bytes.fromFile(File);

// Consumption
byte[]  b.asBytes();
String  b.encode(Encoding);
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
KeyStore keystore(String location, String password, String type, String provider);

// ─── Certificates (com.mirkocaserta.bruce.Keystores) ─────────────────────────
Certificate certificate(KeyStore keystore, String alias);

// ─── Keys (com.mirkocaserta.bruce.Keystores) ─────────────────────────────────
PublicKey  publicKey(KeyStore keystore, String alias);
PrivateKey privateKey(KeyStore keystore, String alias, char[] password);
PrivateKey privateKey(KeyStore keystore, String alias, String password);
Key        secretKey(KeyStore keystore, String alias, char[] password);
Key        secretKey(KeyStore keystore, String alias, String password);
KeyPair    keyPair(String algorithm, int keySize);
KeyPair    keyPair(String algorithm, String provider, int keySize);
KeyPair    keyPair(String algorithm, int keySize, SecureRandom random);
KeyPair    keyPair(String algorithm, String provider, int keySize, SecureRandom random);
byte[]     symmetricKey(String algorithm);
byte[]     symmetricKey(String algorithm, String provider);
String     symmetricKey(String algorithm, Encoding encoding);
String     symmetricKey(String algorithm, String provider, Encoding encoding);

// ─── Digests (Bruce.digestBuilder) ──────────────────────────────────────────
DigestBuilder digestBuilder()
  .algorithm(String)
  .provider(String)    // optional
  .build()             // → Digester

// Digester interface
Bytes  Digester.digest(Bytes input)
Bytes  Digester.digest(Path file)     // streaming
Bytes  Digester.digest(File file)     // delegates to Path variant

// ─── Signatures (Bruce.signerBuilder / verifierBuilder) ─────────────────────
SignerBuilder signerBuilder()
  .key(PrivateKey)                    // single key
  .keys(Map<String, PrivateKey>)      // multi-key
  .algorithm(String)
  .provider(String)                   // optional
  .build()                            // → Signer
  .buildByKey()                       // → SignerByKey

VerifierBuilder verifierBuilder()
  .key(PublicKey)                     // single key
  .keys(Map<String, PublicKey>)       // multi-key
  .algorithm(String)
  .provider(String)                   // optional
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
  .keyAlgorithm(String)              // e.g. "AES"
  .algorithm(String)                 // e.g. "AES/CBC/PKCS5Padding"
  .algorithms(String keyAlgo, String cipherAlgo)  // convenience
  .provider(String)                  // optional
  .buildSymmetricEncryptor()         // → SymmetricEncryptor
  .buildSymmetricDecryptor()         // → SymmetricDecryptor
  .buildSymmetricEncryptorByKey()    // → SymmetricEncryptorByKey (no fixed key)
  .buildSymmetricDecryptorByKey()    // → SymmetricDecryptorByKey

  // asymmetric fixed-key
  .key(Key)                          // PublicKey or PrivateKey
  .algorithm(String)                 // e.g. "RSA"
  .provider(String)                  // optional
  .buildAsymmetricEncryptor()        // → AsymmetricEncryptor
  .buildAsymmetricDecryptor()        // → AsymmetricDecryptor

  // asymmetric by-key
  .keys(Map<String, Key>)
  .buildAsymmetricEncryptorByKey()   // → AsymmetricEncryptorByKey
  .buildAsymmetricDecryptorByKey()   // → AsymmetricDecryptorByKey

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
  .provider(String)                  // optional
  .build()                           // → Mac

// Mac interface
Bytes  Mac.get(Bytes message)
```
