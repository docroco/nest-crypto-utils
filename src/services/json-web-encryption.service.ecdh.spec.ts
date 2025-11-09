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

describe('JsonWebEncryptionService ECDH-ES', () => {
  it('encrypts and decrypts with ECDH-ES/A256GCM', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    })
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_P256_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_P256_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebEncryptionService(ks)
      const jwe = await svc.encrypt('secret', { alg: 'ECDH-ES' })
      const pt = await svc.decrypt(jwe, {
        expectedAlg: 'ECDH-ES',
        expectedEnc: 'A256GCM',
      })
      expect(new TextDecoder().decode(pt)).toBe('secret')
    })
  })

  it('fails on expectedEnc mismatch (ECDH-ES)', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    })
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_P256_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_P256_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebEncryptionService(ks)
      const jwe = await svc.encrypt('secret', { alg: 'ECDH-ES' })
      await expect(
        svc.decrypt(jwe, { expectedAlg: 'ECDH-ES', expectedEnc: 'A256GCM' }),
      ).resolves.toBeInstanceOf(Uint8Array)
      await expect(
        svc.decrypt(jwe, {
          expectedAlg: 'ECDH-ES',
          expectedEnc: 'other' as unknown as JweEnc,
        }),
      ).rejects.toMatchObject({
        code: CryptoErrorCode.INVALID_ENVELOPE,
      })
    })
  })

  it('encrypts and decrypts with ECDH-ES+A256KW', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    })
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_P256_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_P256_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebEncryptionService(ks)
      const jwe = await svc.encrypt('secret', { alg: 'ECDH-ES+A256KW' })
      const pt = await svc.decrypt(jwe, {
        expectedAlg: 'ECDH-ES+A256KW',
        expectedEnc: 'A256GCM',
      })
      expect(new TextDecoder().decode(pt)).toBe('secret')
    })
  })

  it('fails on expectedAlg mismatch (ECDH-ES)', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    })
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_P256_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_P256_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebEncryptionService(ks)
      const jwe = await svc.encrypt('secret', { alg: 'ECDH-ES' })
      await expect(
        svc.decrypt(jwe, { expectedAlg: 'ECDH-ES+A256KW', expectedEnc: 'A256GCM' }),
      ).rejects.toMatchObject({
        code: CryptoErrorCode.INVALID_ENVELOPE,
      })
    })
  })
})
