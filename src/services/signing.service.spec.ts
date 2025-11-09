/* eslint-disable node/prefer-global/buffer -- convenience */
import { generateKeyPairSync } from 'node:crypto'

import { CryptoErrorCode } from '../errors/crypto.error'
import { EnvKeyStore } from '../keystore/env-key-store'

import { SigningService } from './signing.service'

function withEnv<T>(vars: Record<string, string>, fn: () => T): T {
  const old = { ...process.env }
  Object.assign(process.env, vars)
  try {
    return fn()
  } finally {
    process.env = old
  }
}

describe('SigningService', () => {
  it('signs and verifies with Ed25519', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new SigningService(ks, {})
      const sig = await svc.sign('hello')
      expect(sig.alg).toBe('Ed25519')
      const ok = await svc.verify('hello', sig)
      expect(ok).toBe(true)
    })
  })

  it('signs and verifies with RSA-PSS-SHA256', async () => {
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
      const svc = new SigningService(ks, {})
      const sig = await svc.sign('hello', { alg: 'RSA-PSS-SHA256' })
      expect(sig.alg).toBe('RSA-PSS-SHA256')
      const ok = await svc.verify('hello', sig)
      expect(ok).toBe(true)
    })
  })

  it('signs and verifies with P-256', async () => {
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
      const svc = new SigningService(ks, {})
      const sig = await svc.sign('hello', { alg: 'P-256' })
      expect(sig.alg).toBe('P-256')
      const ok = await svc.verify('hello', sig)
      expect(ok).toBe(true)
    })
  })

  it('rejects invalid P-256 signatures', async () => {
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
      const svc = new SigningService(ks, {})
      const sig = await svc.sign('hello', { alg: 'P-256' })
      const ok = await svc.verify('goodbye', sig)
      expect(ok).toBe(false)
    })
  })

  it('rejects signing input exceeding maxSigningInputSize', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new SigningService(ks, { maxSigningInputSize: 100 })
      const largeInput = Buffer.alloc(200)
      await expect(svc.sign(largeInput)).rejects.toMatchObject({
        code: CryptoErrorCode.SIZE_LIMIT_EXCEEDED,
      })
    })
  })

  it('throws on unsupported signing algorithms', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new SigningService(ks, {})
      await expect(
        svc.sign('data', {
          alg: 'RSA-OAEP-256' as unknown as import('../types/alg').SignAlg,
        }),
      ).rejects.toMatchObject({ code: CryptoErrorCode.UNSUPPORTED_ALG })
      await expect(
        svc.verify('data', {
          v: '1',
          alg: 'RSA-OAEP-256' as unknown as import('../types/alg').SignAlg,
          kid,
          sig: 'Invalid',
        }),
      ).rejects.toMatchObject({ code: CryptoErrorCode.UNSUPPORTED_ALG })
    })
  })
})
