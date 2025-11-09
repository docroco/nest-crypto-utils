/* eslint-disable unicorn/prefer-module -- convenience */
/* eslint-disable ts/no-require-imports -- convenience */
/* eslint-disable unicorn/import-style -- convenience */
import { Buffer } from 'node:buffer'

import { Test } from '@nestjs/testing'

import { CryptoService } from '../services/crypto.service'
import { JsonWebEncryptionService } from '../services/json-web-encryption.service'
import { JsonWebSignatureService } from '../services/json-web-signature.service'
import { JsonWebTokenService } from '../services/json-web-token.service'
import { SigningService } from '../services/signing.service'
import { base64UrlEncode } from '../utils/encoding'

import { CryptoModule, KEY_STORE } from './crypto.module'

function withEnv<T>(
  vars: Record<string, string>,
  fn: () => Promise<T> | T,
): Promise<T> | T {
  const saved: Record<string, string | undefined> = {}
  for (const k of Object.keys(vars)) {
    saved[k] = process.env[k]
    process.env[k] = vars[k]
  }
  try {
    return fn()
  } finally {
    for (const k of Object.keys(vars)) {
      if (saved[k] === undefined) delete process.env[k]
      else process.env[k] = saved[k] as string
    }
  }
}

describe('CryptoModule DI', () => {
  it('resolves CryptoService and performs HMAC', async () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 7)),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 8)),
    }
    const moduleRef = await Test.createTestingModule({
      imports: [CryptoModule.register()],
    })
      .overrideProvider(KEY_STORE)
      .useValue(new (require('../keystore/env-key-store').EnvKeyStore)({ env }))
      .compile()

    const svc = moduleRef.get(CryptoService)
    const mac = await svc.hmac('abc')
    expect(mac.alg).toBe('HMAC-SHA256')
    expect(mac.kid).toBe(kid)
  })
})

describe('CryptoModule keystore options', () => {
  it('KEY_STORE provider fails to instantiate when env missing', async () => {
    await expect(
      Test.createTestingModule({
        imports: [CryptoModule.register()],
      }).compile(),
    ).rejects.toBeDefined()
  })

  it('boots with FileKeyStore configuration (async register)', async () => {
    const fs = await import('node:fs/promises')
    const os = await import('node:os')
    const path = await import('node:path')
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ncu-'))

    await fs.writeFile(path.join(tmp, 'active_kid'), 'K1')
    await fs.writeFile(path.join(tmp, 'allowed_kids_aes'), '')
    await fs.writeFile(path.join(tmp, 'allowed_kids_sign'), '')
    await fs.mkdir(path.join(tmp, 'aes'), { recursive: true })
    await fs.mkdir(path.join(tmp, 'hmac'), { recursive: true })
    await fs.mkdir(path.join(tmp, 'ed25519'), { recursive: true })
    await fs.mkdir(path.join(tmp, 'rsaps'), { recursive: true })
    await fs.mkdir(path.join(tmp, 'p256'), { recursive: true })

    await withEnv({}, async () => {
      const moduleRef = await Test.createTestingModule({
        imports: [
          CryptoModule.registerAsync({
            useFactory: async () => ({
              keystore: { type: 'file', file: { directory: tmp } },
            }),
            inject: [],
          }),
        ],
      }).compile()
      expect(moduleRef).toBeDefined()
    })
  })

  it('feature flags exclude providers', async () => {
    const mod = await Test.createTestingModule({
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
      .useValue({
        getActiveKidFor: () => 'K1',
        getAllowedKidsFor: () => ['K1'],
        getSymmetricKey: () => {
          throw new Error('no')
        },
        getHmacKey: () => {
          throw new Error('no')
        },
        getPrivateKey: () => {
          throw new Error('no')
        },
        getPublicKey: () => {
          throw new Error('no')
        },
      })
      .compile()
    expect(() => mod.get(CryptoService)).toThrow()
    expect(() => mod.get(SigningService)).toThrow()
    expect(() => mod.get(JsonWebSignatureService)).toThrow()
    expect(() => mod.get(JsonWebEncryptionService)).toThrow()
    expect(() => mod.get(JsonWebTokenService)).toThrow()
  })

  it('registerAsync respects feature flags from factory options', async () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 7)),
    }

    await withEnv(env, async () => {
      // Module compilation should fail when all features are disabled
      // because NestJS eagerly instantiates providers
      await expect(
        Test.createTestingModule({
          imports: [
            CryptoModule.registerAsync({
              useFactory: async () => ({
                enableSymmetric: false,
                enableHmac: false,
                enableSigning: false,
                enablePassword: false,
                enableRandom: false,
              }),
              inject: [],
            }),
          ],
        }).compile(),
      ).rejects.toThrow('requires')
    })
  })

  it('registerAsync with file keystore but missing directory throws', async () => {
    await expect(
      Test.createTestingModule({
        imports: [
          CryptoModule.registerAsync({
            useFactory: async () => ({
              keystore: { type: 'file' }, // Missing file property
            }),
            inject: [],
          }),
        ],
      }).compile(),
    ).rejects.toThrow('File keystore directory is required')
  })

})
