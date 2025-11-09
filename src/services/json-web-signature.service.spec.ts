import { generateKeyPairSync } from 'node:crypto'

import { EnvKeyStore } from '../keystore/env-key-store'

import { JsonWebSignatureService } from './json-web-signature.service'

function withEnv<T>(vars: Record<string, string>, fn: () => T): T {
  const old = { ...process.env }
  Object.assign(process.env, vars)
  try {
    return fn()
  } finally {
    process.env = old
  }
}

describe('JsonWebSignatureService', () => {
  it('signs and verifies with EdDSA', async () => {
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
      const svc = new JsonWebSignatureService(ks)
      const jws = await svc.sign('hello')
      const out = await svc.verify(jws)
      expect(new TextDecoder().decode(out.payload)).toBe('hello')
    })
  })

  it('fails verification on alg mismatch', async () => {
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
      const svc = new JsonWebSignatureService(ks)
      const jws = await svc.sign('hello', { alg: 'EdDSA' })
      await expect(svc.verify(jws, { expectedAlg: 'PS256' })).rejects.toBeDefined()
    })
  })

  it('canonical signing normalizes object ordering', async () => {
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
      const svc = new JsonWebSignatureService(ks)
      const payloadA = { b: 1, a: 2, z: { y: 3, x: 4 } }
      const payloadB = { z: { x: 4, y: 3 }, a: 2, b: 1 }

      const canonical1 = await svc.sign(payloadA, { canonical: true })
      const canonical2 = await svc.sign(payloadB, { canonical: true })
      expect(canonical1).toBe(canonical2)

      const nonCanonical1 = await svc.sign(payloadA)
      const nonCanonical2 = await svc.sign(payloadB)
      expect(nonCanonical1).not.toBe(nonCanonical2)
    })
  })
})
