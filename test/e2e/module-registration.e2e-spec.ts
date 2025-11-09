/* eslint-disable unicorn/prefer-module -- convenience */
/* eslint-disable ts/no-require-imports -- convenience */
import { Test } from '@nestjs/testing'

import { CryptoModule, KEY_STORE } from '../../src/module/crypto.module'
import { CryptoService } from '../../src/services/crypto.service'
import { JsonWebTokenService } from '../../src/services/json-web-token.service'
import { PasswordService } from '../../src/services/password.service'
import { RandomService } from '../../src/services/random.service'
import { SigningService } from '../../src/services/signing.service'
import { TestKeystoreBuilder } from '../utils/keystore-builders'

import { setupTestKeyDirectory, cleanupTestKeyDirectory } from './fixtures/keys/setup'

import type { INestApplication } from '@nestjs/common'

describe('CryptoModule registration (e2e)', () => {
  describe('default EnvKeyStore', () => {
    let app: INestApplication

    afterEach(async () => {
      await app?.close()
    })

    it('registers with default options', async () => {
      const keystore = new TestKeystoreBuilder()
        .withActiveKid('K1')
        .withAesKey('K1')
        .withHmacKey('K1')
        .withEd25519Keys('K1')
        .build()

      const module = await Test.createTestingModule({
        imports: [CryptoModule.register()],
      })
        .overrideProvider(KEY_STORE)
        .useValue(keystore)
        .compile()

      app = module.createNestApplication()
      await app.init()

      expect(app).toBeDefined()
    })

    it('all services are injectable when enabled', async () => {
      const keystore = new TestKeystoreBuilder()
        .withActiveKid('K1')
        .withAesKey('K1')
        .withHmacKey('K1')
        .withEd25519Keys('K1')
        .build()

      const module = await Test.createTestingModule({
        imports: [
          CryptoModule.register({
            enableSymmetric: true,
            enableHmac: true,
            enableSigning: true,
            enablePassword: true,
            enableRandom: true,
          }),
        ],
      })
        .overrideProvider(KEY_STORE)
        .useValue(keystore)
        .compile()

      app = module.createNestApplication()
      await app.init()

      expect(app.get(CryptoService)).toBeDefined()
      expect(app.get(SigningService)).toBeDefined()
      expect(app.get(JsonWebTokenService)).toBeDefined()
      expect(app.get(PasswordService)).toBeDefined()
      expect(app.get(RandomService)).toBeDefined()
    })

    it('services throw when disabled', async () => {
      const keystore = new TestKeystoreBuilder().withActiveKid('K1').build()

      const module = await Test.createTestingModule({
        imports: [
          CryptoModule.register({
            enableSymmetric: false,
            enableHmac: false,
            enableSigning: false,
            enablePassword: false,
            enableRandom: false,
          }),
        ],
      })
        .overrideProvider(KEY_STORE)
        .useValue(keystore)
        .compile()

      app = module.createNestApplication()
      await app.init()

      expect(() => app.get(CryptoService)).toThrow()
      expect(() => app.get(SigningService)).toThrow()
      expect(() => app.get(PasswordService)).toThrow()
      expect(() => app.get(RandomService)).toThrow()
    })
  })

  describe('FileKeyStore via registerAsync', () => {
    let app: INestApplication
    let keyDir: string

    beforeAll(async () => {
      keyDir = await setupTestKeyDirectory()
    })

    afterAll(async () => {
      await app?.close()
      await cleanupTestKeyDirectory(keyDir)
    })

    it('registers with FileKeyStore', async () => {
      const module = await Test.createTestingModule({
        imports: [
          CryptoModule.registerAsync({
            useFactory: async () => ({
              keystore: {
                type: 'file',
                file: { directory: keyDir },
              },
            }),
            inject: [],
          }),
        ],
      }).compile()

      app = module.createNestApplication()
      await app.init()

      const crypto = app.get(CryptoService)
      expect(crypto).toBeDefined()

      // Test that keystore works
      const envelope = await crypto.encrypt('test')
      const decrypted = await crypto.decryptToString(envelope)
      expect(decrypted).toBe('test')
    })

    it('FileKeyStore reloads pick up changed keys', async () => {
      const module = await Test.createTestingModule({
        imports: [
          CryptoModule.registerAsync({
            useFactory: async () => ({
              keystore: {
                type: 'file',
                file: { directory: keyDir },
              },
            }),
            inject: [],
          }),
        ],
      }).compile()

      app = module.createNestApplication()
      await app.init()

      const crypto = app.get(CryptoService)

      // Initial encryption
      const envelope1 = await crypto.encrypt('test1')
      expect(envelope1.kid).toBe('K1')

      // Verify decryption works
      const decrypted = await crypto.decryptToString(envelope1)
      expect(decrypted).toBe('test1')
    })
  })

  describe('custom module options', () => {
    let app: INestApplication

    afterEach(async () => {
      await app?.close()
    })

    it('respects custom input size limits', async () => {
      const keystore = new TestKeystoreBuilder()
        .withActiveKid('K1')
        .withAesKey('K1')
        .build()

      const module = await Test.createTestingModule({
        imports: [
          CryptoModule.register({
            maxEncryptionInputSize: 100,
          }),
        ],
      })
        .overrideProvider(KEY_STORE)
        .useValue(keystore)
        .compile()

      app = module.createNestApplication()
      await app.init()

      const crypto = app.get(CryptoService)

      // Should work with small input
      await expect(crypto.encrypt('small')).resolves.toBeDefined()

      // Should fail with large input

      const largeInput = require('node:buffer').Buffer.alloc(200, 0xff)
      await expect(crypto.encrypt(largeInput)).rejects.toMatchObject({
        code: 'SIZE_LIMIT_EXCEEDED',
      })
    })

    it('password service uses configured algorithm', async () => {
      const module = await Test.createTestingModule({
        imports: [
          CryptoModule.register({
            enablePassword: true,
            passwordAlgorithm: 'bcrypt',
            bcryptCost: 4, // Low cost for testing
          }),
        ],
      })
        .overrideProvider(KEY_STORE)
        .useValue(new TestKeystoreBuilder().withActiveKid('K1').build())
        .compile()

      app = module.createNestApplication()
      await app.init()

      const password = app.get(PasswordService)
      const hash = await password.hash('test-password')

      expect(hash).toBeDefined()
      expect(hash.startsWith('$2')).toBe(true) // Bcrypt prefix

      const valid = await password.verify('test-password', hash)
      expect(valid).toBe(true)
    })

    it('password service uses argon2 when configured', async () => {
      const module = await Test.createTestingModule({
        imports: [
          CryptoModule.register({
            enablePassword: true,
            passwordAlgorithm: 'argon2',
            argon2: { timeCost: 2, memoryCost: 32 * 1024, parallelism: 1, version: 1 },
          }),
        ],
      })
        .overrideProvider(KEY_STORE)
        .useValue(new TestKeystoreBuilder().withActiveKid('K1').build())
        .compile()

      app = module.createNestApplication()
      await app.init()

      const password = app.get(
        require('../../src/services/password.service').PasswordService,
      )
      const hash = await password.hash('secret')
      expect(hash.startsWith('$argon2')).toBe(true)
      await expect(password.verify('secret', hash)).resolves.toBe(true)
    })
  })

  describe('module is global', () => {
    let app: INestApplication

    afterEach(async () => {
      await app?.close()
    })

    it('services available without reimporting in child modules', async () => {
      const keystore = new TestKeystoreBuilder()
        .withActiveKid('K1')
        .withAesKey('K1')
        .withEd25519Keys('K1')
        .build()

      const module = await Test.createTestingModule({
        imports: [CryptoModule.register()],
      })
        .overrideProvider(KEY_STORE)
        .useValue(keystore)
        .compile()

      app = module.createNestApplication()
      await app.init()

      // Services should be available globally
      const crypto = app.get(CryptoService)
      expect(crypto).toBeDefined()
      expect(crypto).toBeInstanceOf(CryptoService)
    })
  })
})
