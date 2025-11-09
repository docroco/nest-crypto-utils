# @docroco/nest-crypto-utils

[![CI](https://github.com/docroco/nest-crypto-utils/workflows/CI/badge.svg)](https://github.com/docroco/nest-crypto-utils/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/docroco/nest-crypto-utils/branch/main/graph/badge.svg)](https://codecov.io/gh/docroco/nest-crypto-utils)
[![npm version](https://badge.fury.io/js/%40docroco%2Fnest-crypto-utils.svg)](https://www.npmjs.com/package/@docroco/nest-crypto-utils)
[![Security Audit](https://github.com/docroco/nest-crypto-utils/workflows/Security%20Audit/badge.svg)](https://github.com/docroco/nest-crypto-utils/actions/workflows/security-audit.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Opinionated cryptographic utilities for NestJS v11. Safe defaults, DI-first APIs, minimal deps.

- Symmetric encryption: AES-256-GCM (with AAD)
- HMAC: HMAC-SHA-256
- KDFs: PBKDF2-SHA-256, HKDF-SHA-256
- Signing: Ed25519 (default), RSA-PSS-SHA256, ES256 (P-256)
- JOSE: JWS (EdDSA/PS256/ES256), JWE (RSA-OAEP-256 or ECDH-ES[+A256KW] + A256GCM)
- Streaming: AES-GCM encrypt/decrypt and HMAC streaming
- Passwords: bcrypt (default, configurable) or argon2 (configurable) in one service
- Random: secrets and IDs (UUID, ULID, CUID, nanoid)

## Installation

```bash
npm install @docroco/nest-crypto-utils
```

Peer deps (Nest v11): `@nestjs/common`, `@nestjs/core`, `reflect-metadata`, `rxjs`.

## Quick start

Register the module globally:

```ts
import { Module } from '@nestjs/common'
import { CryptoModule } from '@docroco/nest-crypto-utils'

@Module({
  imports: [
    CryptoModule.register({
      // passwordAlgorithm: 'argon2',
      // bcryptCost: 12,
      // argon2: { timeCost: 3, memoryCost: 64 * 1024, parallelism: 1, version: 1 },
    }),
  ],
})
export class AppModule {}
```

Use services via DI:

```ts
import { Injectable } from '@nestjs/common'
import { CryptoService, SigningService } from '@docroco/nest-crypto-utils'

@Injectable()
export class ExampleService {
  constructor(
    private readonly crypto: CryptoService,
    private readonly signing: SigningService,
  ) {}

  async roundtrip(): Promise<string> {
    const envelope = await this.crypto.encrypt('hello', { aad: 'meta' })
    return this.crypto.decryptToString(envelope, { aad: 'meta' })
  }
}
```

## Configuration Reference

| Option | Default | Purpose |
| --- | --- | --- |
| `enableSymmetric` | `true` | Register `CryptoService` and `CryptoStreamService` for AES-GCM helpers. |
| `enableHmac` | `true` | Include HMAC helpers alongside symmetric services. |
| `enableSigning` | `true` | Provide signing, JWS/JWE, and JWT services. |
| `enablePassword` | `true` | Make the `PasswordService` available. |
| `enableRandom` | `true` | Export `RandomService`. |
| `bcryptCost` | `12` | Default bcrypt cost when hashing passwords. |
| `passwordAlgorithm` | `'bcrypt'` | Choose `'bcrypt'` (default) or `'argon2'` for `PasswordService`. |
| `argon2` | `{ timeCost: 3, memoryCost: 64 * 1024, parallelism: 1, version: 1 }` | Override Argon2 parameters when selected. |
| `keystore.type` | `'env'` | Pick key source (`'env'` or `'file'`). |
| `keystore.env` | `{}` | Additional options passed to `EnvKeyStore` (e.g., `{ requireSymmetric: true }`). |
| `keystore.file` | `undefined` | Directory/logger configuration for `FileKeyStore`. |
| `maxEncryptionInputSize` | `10 * 1024 * 1024` | Maximum bytes allowed for non-streaming AES operations. |
| `maxSigningInputSize` | `10 * 1024 * 1024` | Maximum payload size accepted by signing helpers. |
| `maxHmacInputSize` | `10 * 1024 * 1024` | Maximum payload size accepted by HMAC helpers. |

```ts
CryptoModule.register({
  enableSymmetric: true,
  passwordAlgorithm: 'argon2',
  keystore: {
    type: 'file',
    file: { directory: '/etc/app/keys' },
  },
  maxEncryptionInputSize: 5 * 1024 * 1024,
})
```

### Choosing a Keystore

- **EnvKeyStore (default):** Load base64url/PEM key material directly from environment variables. Add enforcement flags via `keystore.env` (e.g., `{ requireSymmetric: true }`).
- **FileKeyStore:** Use `registerAsync` and set `keystore.type` to `'file'` to load from a directory hierarchy managed by ops tooling.
- **InMemoryKeyStore:** Lightweight helper for tests—instantiate manually.

See [docs/keystore-guide.md](docs/keystore-guide.md) for detailed setup, rotation workflows, and troubleshooting advice.

## Terminology

Understanding these terms will help you use the library effectively:

- **kid (Key ID)**: A string identifier for a cryptographic key (e.g., `"prod-2024-01"`, `"K1"`). Used to support key rotation and multi-key scenarios.
- **Active kid**: The default key ID used for new encryption/signing operations when no explicit `kid` is specified.
- **Allowed kids**: A whitelist of key IDs that can be used for decryption/verification, enabling graceful key rotation.
- **Envelope**: A JSON structure containing encrypted data plus metadata (algorithm, kid, IV, tag, AAD). Makes ciphertext self-describing.
- **AAD (Additional Authenticated Data)**: Optional context data bound to the ciphertext (e.g., user ID, request ID). Authenticated but not encrypted.
- **Nonce/IV**: A unique value used once per encryption operation. For AES-GCM, this is a 96-bit random value. **Never reuse** with the same key.
- **Keystore**: An abstraction for loading and managing cryptographic keys. Three implementations: `EnvKeyStore` (environment variables), `FileKeyStore` (filesystem), `InMemoryKeyStore` (testing).
- **JWS (JSON Web Signature)**: A standard for signing JSON payloads. Produces compact tokens like `header.payload.signature`.
- **JWE (JSON Web Encryption)**: A standard for encrypting JSON payloads. Produces compact tokens like `header.encryptedKey.iv.ciphertext.tag`.
- **JWT (JSON Web Token)**: A JWS with standardized claims (`exp`, `iss`, `aud`, etc.). Used for authentication/authorization.
- **JWKS (JSON Web Key Set)**: A JSON structure containing public keys for JWT verification. Can be fetched from remote URLs.
- **Detached signature**: A signature stored separately from the payload, useful when the payload is large or already transmitted.
- **Canonical JSON**: JSON with stable key ordering, ensuring consistent serialization for signatures.

## EnvKeyStore (default keystore)

By default, keys load from environment variables per `kid` (key id). Configure an active `kid` and allowed lists:

- `CRYPTO_ACTIVE_KID`: the current active kid (string)
- `CRYPTO_ALLOWED_KIDS_AES`: comma-separated list of AES/HMAC kids (optional); active kid is implicitly allowed
- `CRYPTO_ALLOWED_KIDS_SIGN`: comma-separated list of signing kids (optional); active kid is implicitly allowed

Per-kid keys:

- Symmetric (AES-256-GCM): `CRYPTO_AES_KEY_<KID>` = base64url(32 bytes)
- HMAC (HMAC-SHA256): `CRYPTO_HMAC_KEY_<KID>` = base64url(>=32 bytes)
- Ed25519 (PEM or base64url):
  - `CRYPTO_ED25519_PRIV_PEM_<KID>` = PKCS8 private PEM
  - `CRYPTO_ED25519_PUB_PEM_<KID>` = SPKI public PEM
  - alternatively `CRYPTO_ED25519_PRIV_<KID>` / `CRYPTO_ED25519_PUB_<KID>` as base64url DER
- RSA-PSS-256 / RSA-OAEP-256 (PEM):
  - `CRYPTO_RSAPS_PRIV_<KID>` = PKCS1/PKCS8 private PEM
  - `CRYPTO_RSAPS_PUB_<KID>` = PKCS1/SPKI public PEM

Notes
- RSA key pair is used for both PS256 (sign/verify) and RSA-OAEP-256 (encrypt/decrypt) by design; consider using distinct kids for sign vs enc.

## Other keystores

- InMemoryKeyStore (tests/dev):

```ts
import { InMemoryKeyStore } from '@docroco/nest-crypto-utils'

const ks = new InMemoryKeyStore({ activeKid: 'K1' })
ks.setSymmetricKey('K1', new Uint8Array(32))
ks.setHmacKey('K1', new Uint8Array(32))
// setEd25519Keys('K1', privPem, pubPem);
// setRsaPssKeys('K1', privPem, pubPem);
```

- FileKeyStore (ops-friendly): load from a directory and call `reload()`:

```
<root>/active_kid                         # text
<root>/allowed_kids_aes                   # comma-separated
<root>/allowed_kids_sign                  # comma-separated
<root>/aes/<kid>.b64u                     # base64url 32 bytes
<root>/hmac/<kid>.b64u                    # base64url >=32 bytes
<root>/ed25519/priv-<kid>.pem             # PKCS8
<root>/ed25519/pub-<kid>.pem              # SPKI
<root>/rsaps/priv-<kid>.pem               # PKCS1/PKCS8
<root>/rsaps/pub-<kid>.pem                # PKCS1/SPKI
```

## Examples

### AES-256-GCM
```ts
const env = await crypto.encrypt('secret', { aad: 'ctx' })
const pt = await crypto.decryptToString(env, { aad: 'ctx' })
```

### HMAC-SHA256
```ts
const mac = await crypto.hmac('payload')
// mac.mac is base64url string
```

### PBKDF2 / HKDF
```ts
const k1 = await crypto.deriveKeyPBKDF2('password', { salt: 'salt', iterations: 100_000, length: 32 })
const k2 = await crypto.deriveKeyHKDF('ikm', { salt: 'salt', info: 'info', length: 32 })
```

### Signing (Ed25519, RSA-PSS)
```ts
const sig = await signing.sign('msg')
const ok = await signing.verify('msg', sig)
```

### JOSE (JWS/JWE)
```ts
const jws = await jwsSvc.sign({ hello: 'world' }, { alg: 'ES256' })
const { payload } = await jwsSvc.verify(jws, { expectedAlg: 'ES256' })

const jwe = await jweSvc.encrypt('secret', { alg: 'ECDH-ES' })
const plaintext = await jweSvc.decrypt(jwe, { expectedAlg: 'ECDH-ES', expectedEnc: 'A256GCM' })
```

Detached JWS:

```ts
// Compact-detached (default): produce header..signature and reattach payload at verify
const jwsDetached = await jwsSvc.sign('payload', { detached: true })
await jwsSvc.verify(jwsDetached, { expectedAlg: 'ES256', detachedPayload: 'payload' })

// RFC 7797 (b64=false) mode
const jwsRfc = await jwsSvc.sign('payload', { detached: true, detachedMode: 'rfc7797', alg: 'EdDSA' })
await jwsSvc.verify(jwsRfc, { expectedAlg: 'EdDSA', detachedPayload: 'payload' })
```

Note: Compact JWE does not support providing Additional Authenticated Data (AAD). If you need AAD with JWE, use flattened/general JWE or prefer envelope encryption via `CryptoService`.

### JWT (EdDSA/PS256/ES256) with optional remote JWKS
```ts
const jwt = await jwtSvc.sign({ role: 'user' }, {
  alg: 'ES256',
  expiresIn: '15m',
  issuer: 'me',
  audience: 'you',
})

// Local keystore verification
const verified = await jwtSvc.verify(jwt, { issuer: 'me', audience: 'you' })

// Remote JWKS verification (explicit URLs)
await jwtSvc.verify(jwt, {
  jwksUrls: ['https://issuer.example.com/.well-known/jwks.json'],
  issuer: 'https://issuer.example.com/',
  audience: 'you',
})

// Remote JWKS via issuer mapping
await jwtSvc.verify(jwt, {
  issuerJwks: [{ issuer: 'https://issuer.example.com/', jwksUrl: 'https://issuer.example.com/.well-known/jwks.json' }],
  audience: 'you',
})

// Local JWKS (inline) verification
// Note: The JWK must be valid for the algorithm in the token and include a matching 'kid'
await jwtSvc.verify(jwt, {
  jwks: {
    keys: [
      // Example Ed25519 JWK shape (replace x with your base64url key and kid appropriately)
      { kty: 'OKP', crv: 'Ed25519', x: 'base64url-public-key', kid: 'K1' },
    ],
  },
  issuer: 'me',
  audience: 'you',
})

// Restrict acceptable algorithms during verification
await jwtSvc.verify(jwt, { algs: ['ES256'] }).catch(() => {
  // Fails if token was signed with a different algorithm (e.g., EdDSA)
})
await jwtSvc.verify(jwt, { algs: ['EdDSA'] }) // Succeeds when allowed list matches token's alg
```

### Advanced Examples

#### Key Rotation with Multiple Kids

```ts
// Encrypt with new key
const envelope = await crypto.encrypt('data', { kid: 'key-v2' })

// Old keys remain available for decryption
const oldEnvelope = { ...someOldEnvelope, kid: 'key-v1' }
const decrypted = await crypto.decrypt(oldEnvelope)
```

#### Streaming Large Files

```ts
import { createReadStream, createWriteStream } from 'node:fs'

// Encrypt a large file
const { meta, cipher } = cryptoStream.createEncryptStream({ aad: 'file-id-123' })
const input = createReadStream('large-file.bin')
const output = createWriteStream('large-file.enc')

input.pipe(cipher).pipe(output)

await new Promise((resolve, reject) => {
  output.on('finish', resolve)
  output.on('error', reject)
})

const { tag } = cryptoStream.finalizeEncryptStream(meta, cipher)
// Store meta and tag alongside encrypted file

// Decrypt the file
const decipher = cryptoStream.createDecryptStream({ ...meta, tag })
const encInput = createReadStream('large-file.enc')
const plainOutput = createWriteStream('large-file.dec')

encInput.pipe(decipher).pipe(plainOutput)
```

> ℹ️ If you routinely hit the `CryptoModule` size limits, raise `maxEncryptionInputSize`
> or stream as shown above.

#### HMAC Streaming for Large Data

```ts
import { createReadStream } from 'node:fs'

const { transform, finalize } = cryptoStream.hmacStream()
const stream = createReadStream('large-file.bin')

stream.pipe(transform)

await new Promise((resolve, reject) => {
  transform.on('finish', resolve)
  transform.on('error', reject)
})

const { mac } = finalize()
// mac is base64url-encoded HMAC-SHA256
```

> ℹ️ Streaming HMAC keeps processing below `maxHmacInputSize`; increase the limit if you
> prefer to hash in-memory instead.

#### Custom Input Size Limits

```ts
// Configure per-operation limits
CryptoModule.register({
  maxEncryptionInputSize: 5 * 1024 * 1024, // 5MB
  maxSigningInputSize: 1 * 1024 * 1024,    // 1MB
  maxHmacInputSize: 10 * 1024 * 1024,      // 10MB
})

// Operations exceeding limits will throw CryptoError with SIZE_LIMIT_EXCEEDED
```

#### Canonical JSON for Deterministic Signatures

```ts
// Ensure stable serialization for signing
const payload = { z: 1, a: 2, m: { y: 3, x: 4 } }
const jws = await jwsSvc.sign(payload, { canonical: true })

// Keys are sorted: { a: 2, m: { x: 4, y: 3 }, z: 1 }
```

#### Password Hashing with Argon2

```ts
// Configure Argon2 instead of bcrypt
CryptoModule.register({
  passwordAlgorithm: 'argon2',
  argon2: {
    timeCost: 3,
    memoryCost: 64 * 1024, // 64 MiB
    parallelism: 1,
    version: 1,
  },
})

// Use the same PasswordService API
const hash = await passwordSvc.hash('secret')
const ok = await passwordSvc.verify('secret', hash)
```

## JWKS endpoint

This library does not expose a JWKS endpoint. It can consume remote JWKS for JWT verification.

## Module registration and keystores

- Default `register()` uses `EnvKeyStore`. You can pass enforcement flags via `keystore.env` in options.
- `FileKeyStore` requires async registration:

```ts
CryptoModule.registerAsync({
  useFactory: async () => ({
    keystore: { type: 'file', file: { directory: '/keys' } },
  }),
})
```

## Security Considerations

### AES-GCM Nonce Management

This library uses **random 96-bit IVs (nonces)** for each AES-256-GCM encryption operation. While this approach uses cryptographically secure random generation, there are important considerations for production use:

#### Nonce Collision Risk

Random nonces are subject to the **birthday paradox**:
- At approximately **2^48 encryptions** with the same key, there's a 50% probability of nonce collision
- **Nonce reuse with AES-GCM is catastrophic** - it completely breaks confidentiality and authenticity
- In distributed systems, the risk increases as multiple instances may generate the same random nonce

#### Recommendations

1. **Rotate keys regularly** using the `kid` (key ID) mechanism:
   ```ts
   // Use versioned keys
   const envelope = await crypto.encrypt(data, { kid: 'app-key-2024-01' })
   ```

2. **Limit encryptions per key** - Conservative guideline: rotate before **2^32 (4.3 billion) operations**

3. **Monitor encryption counts** in production - Track operations per key and automate rotation

4. **In distributed systems**:
   - Use unique keys per instance/region, OR
   - Implement counter-based nonce generation, OR
   - Use a centralized nonce coordination service

5. **Key rotation example**:
   ```ts
   // Environment variables for key rotation
   // CRYPTO_ACTIVE_KID=key-v2
   // CRYPTO_ALLOWED_KIDS_AES=key-v1,key-v2
   // CRYPTO_AES_KEY_key-v1=... (old key, kept for decryption)
   // CRYPTO_AES_KEY_key-v2=... (new key, used for encryption)
   
   // Encryption automatically uses active key
   const envelope = await crypto.encrypt('data')
   // envelope.kid will be 'key-v2'
   
   // Decryption works with any allowed key
   const plaintext = await crypto.decrypt(oldEnvelope)
   // Works even if oldEnvelope.kid is 'key-v1'
   ```

### Other Security Notes

- **AAD (Additional Authenticated Data)** is supported and verified for AES-GCM
- **Error codes** surface via `CryptoError` to aid handling without leaking secrets
- **RSA-OAEP-256** is intended for small payloads; use envelope encryption for larger data
- **Separate keys for signing vs encryption** - While RSA keys can be used for both, use distinct `kid` values for different purposes
- **Timing-safe comparisons** are used for AAD validation to prevent timing attacks

## Random IDs

- `randomString(NanoidStringEnum.UUID)` returns an RFC 4122 UUID v4 and ignores the length parameter.

### Random secrets

```ts
// Base64url-encoded secret (default). 32 bytes of entropy (~43 chars)
const s1 = await random.generateSecret(32)

// Hex-encoded secret. 16 bytes of entropy → 32 hex chars
const s2 = await random.generateSecret(16, 'hex')
```

## Troubleshooting

### Common Errors and Solutions

#### `KEY_NOT_FOUND` Error

**Symptom**: `CryptoError: KEY_NOT_FOUND - AES key not found` or similar.

**Causes**:
- Environment variable not set for the requested `kid`
- Typo in `kid` name
- Key not loaded in `FileKeyStore` directory
- `kid` not in allowed list

**Solutions**:
```bash
# Check environment variables are set
echo $CRYPTO_ACTIVE_KID
echo $CRYPTO_AES_KEY_K1

# Verify kid matches exactly (case-sensitive)
# For FileKeyStore, check file exists:
ls -la /path/to/keys/aes/K1.b64u

# Verify kid is in allowed list or is the active kid
echo $CRYPTO_ALLOWED_KIDS_AES
```

#### `INVALID_KEY_MATERIAL` Error

**Symptom**: `CryptoError: INVALID_KEY_MATERIAL - AES key must be 32 bytes` or key parsing errors.

**Causes**:
- Wrong key length (AES needs exactly 32 bytes, HMAC needs ≥32 bytes)
- Invalid base64url encoding
- Wrong PEM format for signing keys
- Corrupted key data

**Solutions**:
```bash
# Generate correct AES key (32 bytes = 43 base64url chars)
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"

# Generate correct HMAC key
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"

# For Ed25519 keys, ensure PEM format:
# CRYPTO_ED25519_PRIV_PEM_K1="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"

# Verify base64url has no padding (=) or invalid chars (+, /)
```

#### `DECRYPT_AUTH_FAILED` Error

**Symptom**: `CryptoError: DECRYPT_AUTH_FAILED - Decryption/authentication failed`.

**Causes**:
- Wrong decryption key (kid mismatch)
- Ciphertext tampered with
- AAD mismatch (provided AAD doesn't match envelope AAD)
- Corrupted envelope data

**Solutions**:
```ts
// Verify kid matches
console.log('Envelope kid:', envelope.kid)
console.log('Active kid:', process.env.CRYPTO_ACTIVE_KID)

// Check AAD consistency
const envelope = await crypto.encrypt('data', { aad: 'user-123' })
// Must decrypt with same AAD
await crypto.decrypt(envelope, { aad: 'user-123' }) // ✓ Works
await crypto.decrypt(envelope, { aad: 'user-456' }) // ✗ Fails
await crypto.decrypt(envelope) // ✗ Fails (AAD mismatch)

// Verify envelope structure
console.log(JSON.stringify(envelope, null, 2))
```

#### `SIZE_LIMIT_EXCEEDED` Error

**Symptom**: `CryptoError: SIZE_LIMIT_EXCEEDED - plaintext exceeds maximum size`.

**Causes**:
- Input data too large for configured limits
- Trying to encrypt/sign very large payloads

**Solutions**:
```ts
// Increase limits in module configuration
CryptoModule.register({
  maxEncryptionInputSize: 50 * 1024 * 1024, // 50MB
  maxSigningInputSize: 10 * 1024 * 1024,    // 10MB
})

// Or use streaming for large data
const { meta, cipher } = cryptoStream.createEncryptStream()
largeFileStream.pipe(cipher).pipe(outputStream)
```

### Environment Variable Setup Issues

**Problem**: Keys not loading from environment.

**Checklist**:
```bash
# 1. Verify all required variables are set
env | grep CRYPTO_

# 2. Check for whitespace/newlines in values
printf '%s' "$CRYPTO_AES_KEY_K1" | xxd | head

# 3. Ensure no shell escaping issues
# Use single quotes to avoid interpretation
export CRYPTO_AES_KEY_K1='your-base64url-key-here'

# 4. For Docker/containers, verify env vars passed through
docker run --env-file .env your-image

# 5. For NestJS ConfigModule integration
import { ConfigModule } from '@nestjs/config'
@Module({
  imports: [
    ConfigModule.forRoot(),
    CryptoModule.register(),
  ],
})
```

### Key Rotation Best Practices

**Scenario**: Rotating keys without downtime.

**Steps**:
1. Generate new key with new `kid`
2. Add to `CRYPTO_ALLOWED_KIDS_AES` (comma-separated)
3. Deploy with both old and new keys
4. Update `CRYPTO_ACTIVE_KID` to new `kid`
5. Wait for all old ciphertexts to be re-encrypted
6. Remove old key from allowed list

```bash
# Step 1-2: Add new key
export CRYPTO_ALLOWED_KIDS_AES="key-v1,key-v2"
export CRYPTO_AES_KEY_key-v1="old-key..."
export CRYPTO_AES_KEY_key-v2="new-key..."

# Step 3: Deploy (both keys available for decryption)

# Step 4: Switch active key
export CRYPTO_ACTIVE_KID="key-v2"

# Step 5: Monitor and re-encrypt old data

# Step 6: Remove old key (after grace period)
export CRYPTO_ALLOWED_KIDS_AES="key-v2"
unset CRYPTO_AES_KEY_key-v1
```

### Performance Considerations

**Large Payloads**:
- Use `CryptoStreamService` for files >10MB
- Consider streaming HMAC for large data verification
- Batch operations when possible

**High Throughput**:
- Reuse service instances (injected via DI)
- Avoid creating new keystores repeatedly
- Consider caching derived keys (PBKDF2/HKDF)

**JWT Verification**:
- Remote JWKS adds network latency
- Set appropriate `cacheTtlSeconds` (default 300s)
- Use `timeoutMs` to prevent hanging (default 3000ms)
- Consider local keystore for internal JWTs

### TypeScript Type Issues

**Problem**: Type errors with envelope structures.

**Solution**: Use type guards for runtime validation:
```ts
import { isEnvelopeV1 } from '@docroco/nest-crypto-utils'

const data = JSON.parse(untrustedInput)
if (isEnvelopeV1(data)) {
  // TypeScript knows data is EnvelopeV1
  const plaintext = await crypto.decrypt(data)
} else {
  throw new Error('Invalid envelope structure')
}
```

**Problem**: Module import errors.

**Solution**: Ensure peer dependencies are installed:
```bash
npm install @nestjs/common@^11.0.0 @nestjs/core@^11.0.0 reflect-metadata rxjs
```

## License
MIT
