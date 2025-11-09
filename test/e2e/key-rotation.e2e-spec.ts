import { Test } from '@nestjs/testing'

import { CryptoModule, KEY_STORE } from '../../src/module/crypto.module'
import { CryptoService } from '../../src/services/crypto.service'
import { TestKeystoreBuilder } from '../utils/keystore-builders'

import type { InMemoryKeyStore } from '../../src/keystore/in-memory-key-store'
import type { EnvelopeV1 } from '../../src/types/envelope'
import type { INestApplication } from '@nestjs/common'

describe('Key rotation workflows (e2e)', () => {
  let app: INestApplication
  let keystore: InMemoryKeyStore
  let crypto: CryptoService

  beforeAll(async () => {
    // Start with key-v1 active
    keystore = new TestKeystoreBuilder()
      .withActiveKid('key-v1')
      .withAesKey('key-v1')
      .withAesKey('key-v2')
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
  })

  afterAll(async () => {
    await app?.close()
  })

  it('encrypts with old key, decrypts after key rotation', async () => {
    const data = 'data encrypted with v1'

    // Encrypt with key-v1 (current active)
    const envelope = await crypto.encrypt(data)
    expect(envelope.kid).toBe('key-v1')

    // Rotate active key to key-v2
    keystore.setActiveKid('key-v2')

    // Should still be able to decrypt envelope encrypted with key-v1
    const decrypted = await crypto.decryptToString(envelope)
    expect(decrypted).toBe(data)
  })

  it('encrypts with new active key after rotation', async () => {
    // Key-v2 is now active from previous test

    const data = 'data encrypted with v2'
    const envelope = await crypto.encrypt(data)

    // New encryptions use active key
    expect(envelope.kid).toBe('key-v2')

    // Decrypt works
    const decrypted = await crypto.decryptToString(envelope)
    expect(decrypted).toBe(data)
  })

  it('multiple kids coexist and decrypt correctly', async () => {
    // Create keystore with multiple keys
    const multiKeystore = new TestKeystoreBuilder()
      .withActiveKid('key-v3')
      .withAesKey('key-v1')
      .withAesKey('key-v2')
      .withAesKey('key-v3')
      .build()

    const module = await Test.createTestingModule({
      imports: [CryptoModule.register()],
    })
      .overrideProvider(KEY_STORE)
      .useValue(multiKeystore)
      .compile()

    const testApp = module.createNestApplication()
    await testApp.init()

    const testCrypto = testApp.get(CryptoService)

    // Encrypt with v3 (active)
    const data3 = 'encrypted with v3'
    const env3 = await testCrypto.encrypt(data3)
    expect(env3.kid).toBe('key-v3')

    // Simulate receiving envelopes encrypted with different keys
    multiKeystore.setActiveKid('key-v1')
    const env1 = await testCrypto.encrypt('encrypted with v1')
    expect(env1.kid).toBe('key-v1')

    multiKeystore.setActiveKid('key-v2')
    const env2 = await testCrypto.encrypt('encrypted with v2')
    expect(env2.kid).toBe('key-v2')

    // All should decrypt correctly
    expect(await testCrypto.decryptToString(env1)).toBe('encrypted with v1')
    expect(await testCrypto.decryptToString(env2)).toBe('encrypted with v2')
    expect(await testCrypto.decryptToString(env3)).toBe(data3)

    await testApp.close()
  })

  it('handles key rotation with concurrent operations', async () => {
    const rotationKeystore = new TestKeystoreBuilder()
      .withActiveKid('k1')
      .withAesKey('k1')
      .withAesKey('k2')
      .build()

    const module = await Test.createTestingModule({
      imports: [CryptoModule.register()],
    })
      .overrideProvider(KEY_STORE)
      .useValue(rotationKeystore)
      .compile()

    const testApp = module.createNestApplication()
    await testApp.init()

    const testCrypto = testApp.get(CryptoService)

    // Encrypt some data with k1
    const envelopes: EnvelopeV1[] = []
    for (let i = 0; i < 10; i++) {
      envelopes.push(await testCrypto.encrypt(`message-${i}`))
    }

    // Rotate to k2
    rotationKeystore.setActiveKid('k2')

    // Encrypt some more with k2
    for (let i = 10; i < 20; i++) {
      envelopes.push(await testCrypto.encrypt(`message-${i}`))
    }

    // All should decrypt correctly
    const decrypted = await Promise.all(
      envelopes.map((env, _i) => testCrypto.decryptToString(env)),
    )

    for (const [i, text] of decrypted.entries()) {
      expect(text).toBe(`message-${i}`)
    }

    await testApp.close()
  })

  it('graceful key rotation scenario: old + new both available', async () => {
    // Simulate production key rotation:
    // 1. Deploy with both old and new keys
    // 2. Start using new key for encryption
    // 3. Old key still available for decryption

    const productionKeystore = new TestKeystoreBuilder()
      .withActiveKid('prod-key-2024-01')
      .withAesKey('prod-key-2024-01')
      .withAesKey('prod-key-2024-02')
      .build()

    const module = await Test.createTestingModule({
      imports: [CryptoModule.register()],
    })
      .overrideProvider(KEY_STORE)
      .useValue(productionKeystore)
      .compile()

    const testApp = module.createNestApplication()
    await testApp.init()

    const testCrypto = testApp.get(CryptoService)

    // Step 1: Encrypt data with old key
    const oldData = 'data from before rotation'
    const oldEnvelope = await testCrypto.encrypt(oldData)
    expect(oldEnvelope.kid).toBe('prod-key-2024-01')

    // Step 2: Rotate to new key
    productionKeystore.setActiveKid('prod-key-2024-02')

    // Step 3: New encryptions use new key
    const newData = 'data after rotation'
    const newEnvelope = await testCrypto.encrypt(newData)
    expect(newEnvelope.kid).toBe('prod-key-2024-02')

    // Step 4: Both old and new can be decrypted
    expect(await testCrypto.decryptToString(oldEnvelope)).toBe(oldData)
    expect(await testCrypto.decryptToString(newEnvelope)).toBe(newData)

    await testApp.close()
  })
})
