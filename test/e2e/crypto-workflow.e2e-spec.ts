import { Test } from '@nestjs/testing'

import { CryptoModule, KEY_STORE } from '../../src/module/crypto.module'
import { CryptoService } from '../../src/services/crypto.service'
import { JsonWebEncryptionService } from '../../src/services/json-web-encryption.service'
import { JsonWebSignatureService } from '../../src/services/json-web-signature.service'
import { JsonWebTokenService } from '../../src/services/json-web-token.service'
import { SigningService } from '../../src/services/signing.service'
import { TestKeystoreBuilder } from '../utils/keystore-builders'

import type { INestApplication } from '@nestjs/common'

describe('Crypto workflow (e2e)', () => {
  let app: INestApplication
  let crypto: CryptoService
  let signing: SigningService
  let jws: JsonWebSignatureService
  let jwe: JsonWebEncryptionService
  let jwt: JsonWebTokenService

  beforeAll(async () => {
    const keystore = new TestKeystoreBuilder()
      .withActiveKid('K1')
      .withAesKey('K1')
      .withHmacKey('K1')
      .withEd25519Keys('K1')
      .withRsaPssKeys('K1')
      .withP256Keys('K1')
      .build()

    const module = await Test.createTestingModule({
      imports: [CryptoModule.register()],
    })
      .overrideProvider(KEY_STORE)
      .useValue(keystore)
      .compile()

    app = module.createNestApplication()
    await app.init()

    crypto = app.get(CryptoService)
    signing = app.get(SigningService)
    jws = app.get(JsonWebSignatureService)
    jwe = app.get(JsonWebEncryptionService)
    jwt = app.get(JsonWebTokenService)
  })

  afterAll(async () => {
    await app?.close()
  })

  it('complete encrypt → serialize → deserialize → decrypt workflow', async () => {
    const original = 'sensitive data'
    const aad = 'user-123'

    // Encrypt
    const envelope = await crypto.encrypt(original, { aad })
    expect(envelope.v).toBe('1')
    expect(envelope.kid).toBe('K1')

    // Simulate storage/retrieval (JSON serialize)
    const stored = JSON.stringify(envelope)
    expect(stored).toContain('"v":"1"')

    const retrieved = JSON.parse(stored)
    expect(retrieved.kid).toBe('K1')

    // Decrypt
    const decrypted = await crypto.decryptToString(retrieved, { aad })
    expect(decrypted).toBe(original)
  })

  it('HMAC workflow with verification', async () => {
    const payload = 'important message'

    // Compute HMAC
    const mac = await crypto.hmac(payload)
    expect(mac.v).toBe('1')
    expect(mac.alg).toBe('HMAC-SHA256')
    expect(mac.kid).toBe('K1')
    expect(mac.mac).toBeDefined()

    // Serialize and deserialize
    const stored = JSON.stringify(mac)
    const retrieved = JSON.parse(stored)

    // Re-compute HMAC and compare
    const mac2 = await crypto.hmac(payload)
    expect(mac2.mac).toBe(retrieved.mac)
  })

  it('signing workflow with Ed25519', async () => {
    const message = 'sign this message'

    // Sign
    const signature = await signing.sign(message)
    expect(signature.v).toBe('1')
    expect(signature.alg).toBe('Ed25519')

    // Serialize
    const stored = JSON.stringify(signature)
    const retrieved = JSON.parse(stored)

    // Verify
    const valid = await signing.verify(message, retrieved)
    expect(valid).toBe(true)

    // Verify fails with wrong message
    const invalid = await signing.verify('wrong message', retrieved)
    expect(invalid).toBe(false)
  })

  it('signing workflow with RSA-PSS', async () => {
    const message = 'rsa signed message'

    const signature = await signing.sign(message, { alg: 'RSA-PSS-SHA256' })
    expect(signature.alg).toBe('RSA-PSS-SHA256')

    const valid = await signing.verify(message, signature)
    expect(valid).toBe(true)
  })

  it('signing workflow with P-256', async () => {
    const message = 'p256 signed message'

    const signature = await signing.sign(message, { alg: 'P-256' })
    expect(signature.alg).toBe('P-256')

    const valid = await signing.verify(message, signature)
    expect(valid).toBe(true)
  })

  it('JWS sign and verify workflow', async () => {
    const payload = { hello: 'world', timestamp: Date.now() }

    // Sign
    const jwsToken = await jws.sign(payload, { alg: 'EdDSA' })
    expect(typeof jwsToken).toBe('string')
    expect(jwsToken.split('.')).toHaveLength(3)

    // Verify
    const verified = await jws.verify(jwsToken, { expectedAlg: 'EdDSA' })
    expect(verified.payload).toBeInstanceOf(Uint8Array)

    const parsed = JSON.parse(new TextDecoder().decode(verified.payload))
    expect(parsed.hello).toBe('world')
    expect(parsed.timestamp).toBe(payload.timestamp)
  })

  it('JWE encrypt and decrypt workflow', async () => {
    const plaintext = 'secret message for JWE'

    // Encrypt
    const jweToken = await jwe.encrypt(plaintext, { alg: 'RSA-OAEP-256' })
    expect(typeof jweToken).toBe('string')
    expect(jweToken.split('.')).toHaveLength(5)

    // Decrypt
    const decrypted = await jwe.decrypt(jweToken, {
      expectedAlg: 'RSA-OAEP-256',
      expectedEnc: 'A256GCM',
    })
    expect(new TextDecoder().decode(decrypted)).toBe(plaintext)
  })

  it('JWT sign and verify workflow', async () => {
    const claims = { userId: '12345', role: 'admin', email: 'test@example.com' }

    // Sign JWT
    const token = await jwt.sign(claims, {
      alg: 'EdDSA',
      expiresIn: '1h',
      issuer: 'test-service',
      audience: 'api',
    })
    expect(typeof token).toBe('string')
    expect(token.split('.')).toHaveLength(3)

    // Verify JWT
    const verified = await jwt.verify(token, {
      issuer: 'test-service',
      audience: 'api',
    })
    expect(verified.payload.userId).toBe('12345')
    expect(verified.payload.role).toBe('admin')
    expect(verified.payload.email).toBe('test@example.com')
    expect(verified.payload.exp).toBeDefined()
    expect(verified.payload.iat).toBeDefined()
  })

  it('cross-service workflow: encrypt, sign, verify, decrypt', async () => {
    const secret = 'multi-stage secret'

    // Step 1: Encrypt the secret
    const encrypted = await crypto.encrypt(secret)

    // Step 2: Sign the envelope
    const envelopeStr = JSON.stringify(encrypted)
    const signature = await signing.sign(envelopeStr)

    // Step 3: Simulate transmission (serialize everything)
    const transmission = {
      envelope: encrypted,
      signature,
    }
    const serialized = JSON.stringify(transmission)

    // Step 4: Receive and deserialize
    const received = JSON.parse(serialized)

    // Step 5: Verify signature
    const envelopeStrReceived = JSON.stringify(received.envelope)
    const signatureValid = await signing.verify(envelopeStrReceived, received.signature)
    expect(signatureValid).toBe(true)

    // Step 6: Decrypt the secret
    const decrypted = await crypto.decryptToString(received.envelope)
    expect(decrypted).toBe(secret)
  })

  it('handles concurrent operations gracefully', async () => {
    const promises = Array.from({ length: 50 }, async (_, i) => {
      const data = `message-${i}`
      const envelope = await crypto.encrypt(data)
      const decrypted = await crypto.decryptToString(envelope)
      return decrypted === data
    })

    const results = await Promise.all(promises)
    expect(results.every(r => r === true)).toBe(true)
  })
})
