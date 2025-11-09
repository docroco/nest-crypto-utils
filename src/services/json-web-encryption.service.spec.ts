import { generateKeyPairSync } from 'node:crypto'

import { CryptoErrorCode } from '../errors/crypto.error'
import { EnvKeyStore } from '../keystore/env-key-store'

import { JsonWebEncryptionService } from './json-web-encryption.service'

import type { JweEnc } from '../types/jose'

function withEnv<T>(vars: Record<string, string>, fn: () => T): T {
  const old = { ...process.env }
  Object.assign(process.env, vars)
  try {
    return fn()
  } finally {
    process.env = old
  }
}

describe('JsonWebEncryptionService', () => {
  it('encrypts and decrypts with RSA-OAEP-256/A256GCM', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_RSAPS_PRIV_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
      [`CRYPTO_RSAPS_PUB_${kid}`]: publicKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebEncryptionService(ks)
      const jwe = await svc.encrypt('secret')
      const pt = await svc.decrypt(jwe)
      expect(new TextDecoder().decode(pt)).toBe('secret')
    })
  })

  it('verifies with expectedEnc and expectedAlg', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_RSAPS_PRIV_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
      [`CRYPTO_RSAPS_PUB_${kid}`]: publicKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebEncryptionService(ks)
      const jwe = await svc.encrypt('secret')
      await expect(
        svc.decrypt(jwe, { expectedEnc: 'A256GCM', expectedAlg: 'RSA-OAEP-256' }),
      ).resolves.toBeInstanceOf(Uint8Array)
    })
  })

  it('fails on expectedAlg mismatch (RSA)', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_RSAPS_PRIV_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
      [`CRYPTO_RSAPS_PUB_${kid}`]: publicKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebEncryptionService(ks)
      const jwe = await svc.encrypt('secret', { alg: 'RSA-OAEP-256' })
      await expect(svc.decrypt(jwe, { expectedAlg: 'ECDH-ES' })).rejects.toMatchObject({
        code: CryptoErrorCode.INVALID_ENVELOPE,
      })
    })
  })

  it('fails on expectedEnc mismatch (RSA)', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_RSAPS_PRIV_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
      [`CRYPTO_RSAPS_PUB_${kid}`]: publicKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebEncryptionService(ks)
      const jwe = await svc.encrypt('secret', { alg: 'RSA-OAEP-256' })
      await expect(
        svc.decrypt(jwe, { expectedAlg: 'RSA-OAEP-256', expectedEnc: 'A256GCM' }),
      ).resolves.toBeInstanceOf(Uint8Array)
      await expect(
        svc.decrypt(jwe, {
          expectedAlg: 'RSA-OAEP-256',
          expectedEnc: 'A128GCM' as unknown as JweEnc,
        }),
      ).rejects.toMatchObject({
        code: CryptoErrorCode.INVALID_ENVELOPE,
      })
    })
  })

  it('rejects when zip=DEF compression requested (not supported by jose)', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_RSAPS_PRIV_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
      [`CRYPTO_RSAPS_PUB_${kid}`]: publicKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebEncryptionService(ks)
      await expect(svc.encrypt('secret payload', { zip: 'DEF' })).rejects.toBeDefined()
    })
  })
})
