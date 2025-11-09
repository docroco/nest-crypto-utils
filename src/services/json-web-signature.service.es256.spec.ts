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

describe('JsonWebSignatureService ES256', () => {
  it('signs and verifies with ES256 (P-256)', async () => {
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
      const jws = await svc.sign('hello', { alg: 'ES256' })
      const out = await svc.verify(jws, { expectedAlg: 'ES256' })
      expect(new TextDecoder().decode(out.payload)).toBe('hello')
    })
  })
})
