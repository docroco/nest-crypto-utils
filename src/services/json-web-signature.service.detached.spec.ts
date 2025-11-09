/* eslint-disable unicorn/prefer-module -- convenience */
/* eslint-disable ts/no-require-imports -- convenience */
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

describe('JsonWebSignatureService detached JWS', () => {
  it('signs and verifies detached with ES256', async () => {
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
      const svc = new JsonWebSignatureService(ks)
      const jws = await svc.sign('hello', { alg: 'ES256', detached: true })
      const out = await svc.verify(jws, {
        expectedAlg: 'ES256',
        detachedPayload: 'hello',
      })
      expect(new TextDecoder().decode(out.payload)).toBe('hello')
    })
  })

  it('fails verification when detachedPayload missing', async () => {
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
      const svc = new JsonWebSignatureService(ks)
      const jws = await svc.sign('hello', { alg: 'ES256', detached: true })
      await expect(svc.verify(jws, { expectedAlg: 'ES256' })).rejects.toBeDefined()
    })
  })

  it('signs and verifies detached with EdDSA (Ed25519)', async () => {
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
      const jws = await svc.sign('message', { alg: 'EdDSA', detached: true })
      const out = await svc.verify(jws, {
        expectedAlg: 'EdDSA',
        detachedPayload: 'message',
      })
      expect(new TextDecoder().decode(out.payload)).toBe('message')
    })
  })

  it('signs and verifies detached with PS256 (RSA-PSS)', async () => {
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
      const svc = new JsonWebSignatureService(ks)
      const jws = await svc.sign('payload', { alg: 'PS256', detached: true })
      const out = await svc.verify(jws, {
        expectedAlg: 'PS256',
        detachedPayload: 'payload',
      })
      expect(new TextDecoder().decode(out.payload)).toBe('payload')
    })
  })

  it('RFC7797 detached (b64=false) with EdDSA', async () => {
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
      const jws = await svc.sign('data', {
        alg: 'EdDSA',
        detached: true,
        detachedMode: 'rfc7797',
      })
      const out = await svc.verify(jws, { expectedAlg: 'EdDSA', detachedPayload: 'data' })
      expect(new TextDecoder().decode(out.payload)).toBe('data')
    })
  })

  it('RFC7797 detached handles binary payload', async () => {
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
      const payload = new Uint8Array([0x00, 0xff, 0x7f, 0x10])
      const jws = await svc.sign(payload, {
        alg: 'EdDSA',
        detached: true,
        detachedMode: 'rfc7797',
      })
      const out = await svc.verify(jws, {
        expectedAlg: 'EdDSA',
        detachedPayload: payload,
      })
      expect(require('node:buffer').Buffer.from(out.payload)).toEqual(
        require('node:buffer').Buffer.from(payload),
      )
    })
  })
})
