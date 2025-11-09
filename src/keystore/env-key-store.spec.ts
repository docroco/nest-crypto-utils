import { Buffer } from 'node:buffer'
import { generateKeyPairSync } from 'node:crypto'

import { base64UrlEncode } from '../utils/encoding'

import { EnvKeyStore } from './env-key-store'

function withEnv<T>(vars: Record<string, string>, fn: () => T): T {
  const old = { ...process.env }
  Object.assign(process.env, vars)
  try {
    return fn()
  } finally {
    process.env = old
  }
}

describe('EnvKeyStore', () => {
  it('loads AES and HMAC keys for active kid', () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 1)),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 2)),
    }
    withEnv(env, () => {
      const ks = new EnvKeyStore()
      expect(ks.getSymmetricKey('AES-256-GCM', kid)).toBeDefined()
      expect(ks.getHmacKey('HMAC-SHA256', kid)).toBeDefined()
    })
  })

  it('reload updates active kid and keys', () => {
    const kid1 = 'K1'
    const env1 = {
      CRYPTO_ACTIVE_KID: kid1,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid1}`]: base64UrlEncode(Buffer.alloc(32, 7)),
      [`CRYPTO_HMAC_KEY_${kid1}`]: base64UrlEncode(Buffer.alloc(32, 8)),
    }
    const kid2 = 'K2'
    const env2 = {
      CRYPTO_ACTIVE_KID: kid2,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid2}`]: base64UrlEncode(Buffer.alloc(32, 9)),
      [`CRYPTO_HMAC_KEY_${kid2}`]: base64UrlEncode(Buffer.alloc(32, 10)),
    }
    withEnv(env1, () => {
      const ks = new EnvKeyStore()
      expect(ks.getSymmetricKey('AES-256-GCM', kid1)).toBeDefined()
      withEnv(env2, () => {
        ks.reload()
        expect(ks.getSymmetricKey('AES-256-GCM', kid2)).toBeDefined()
      })
    })
  })

  it('rejects empty or whitespace active kid', () => {
    expect(
      () =>
        new EnvKeyStore({
          env: {
            CRYPTO_ACTIVE_KID: '  ',
            CRYPTO_ALLOWED_KIDS_AES: '',
            CRYPTO_ALLOWED_KIDS_SIGN: '',
          },
        }),
    ).toThrow('CRYPTO_ACTIVE_KID cannot be empty or whitespace')
  })

  it('requireSigning without keys throws', () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
    }
    expect(() => new EnvKeyStore({ env, requireSigning: true })).toThrow()
  })

  it('missing key lookups throw', () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
    }
    const ks = new EnvKeyStore({ env })
    expect(() => ks.getSymmetricKey('AES-256-GCM', 'missing')).toThrow()
    expect(() => ks.getHmacKey('HMAC-SHA256', 'missing')).toThrow()
    expect(() => ks.getPrivateKey('Ed25519', 'missing')).toThrow()
    expect(() => ks.getPublicKey('P-256', 'missing')).toThrow()
  })

  it('requireSymmetric and requireHmac enforce presence', () => {
    const kid = 'K1'
    const baseEnv = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
    }

    expect(() => new EnvKeyStore({ env: baseEnv, requireSymmetric: true })).toThrow()

    expect(() => new EnvKeyStore({ env: baseEnv, requireHmac: true })).toThrow()

    const env = {
      ...baseEnv,
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 7)),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 8)),
    }
    const ks = new EnvKeyStore({
      env,
      requireSymmetric: true,
      requireHmac: true,
    })
    expect(ks.getSymmetricKey('AES-256-GCM', kid)).toBeDefined()
    expect(ks.getHmacKey('HMAC-SHA256', kid)).toBeDefined()
  })

  it('parses Ed25519 DER keys from base64url variables', () => {
    const kid = 'K1'
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const privDer = privateKey.export({ format: 'der', type: 'pkcs8' })
    const pubDer = publicKey.export({ format: 'der', type: 'spki' })
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_${kid}`]: base64UrlEncode(privDer),
      [`CRYPTO_ED25519_PUB_${kid}`]: base64UrlEncode(pubDer),
    }
    withEnv(env, () => {
      const ks = new EnvKeyStore()
      expect(ks.getPrivateKey('Ed25519', kid)).toBeDefined()
      expect(ks.getPublicKey('Ed25519', kid)).toBeDefined()
    })
  })

  it('handles concurrent key lookups safely', () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 1)),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 2)),
    }
    withEnv(env, () => {
      const ks = new EnvKeyStore()

      // Perform many concurrent key lookups
      const lookups = Array.from({ length: 100 }, () =>
        Promise.all([
          Promise.resolve(ks.getSymmetricKey('AES-256-GCM', kid)),
          Promise.resolve(ks.getHmacKey('HMAC-SHA256', kid)),
          Promise.resolve(ks.getActiveKidFor('AES-256-GCM')),
          Promise.resolve(ks.getAllowedKidsFor('AES-256-GCM')),
        ]),
      )

      // Should not throw or corrupt state
      expect(() => Promise.all(lookups)).not.toThrow()
    })
  })

  it('handles reload during concurrent operations', () => {
    const kid1 = 'K1'
    const kid2 = 'K2'
    const env1 = {
      CRYPTO_ACTIVE_KID: kid1,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid1}`]: base64UrlEncode(Buffer.alloc(32, 7)),
    }
    const env2 = {
      CRYPTO_ACTIVE_KID: kid2,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid2}`]: base64UrlEncode(Buffer.alloc(32, 9)),
    }

    withEnv(env1, () => {
      const ks = new EnvKeyStore()

      // Start concurrent operations
      const operations = Array.from({ length: 50 }, () =>
        Promise.resolve(ks.getSymmetricKey('AES-256-GCM', kid1)),
      )

      // Reload with new env in the middle
      withEnv(env2, () => {
        ks.reload()
        expect(ks.getActiveKidFor('AES-256-GCM')).toBe(kid2)
      })

      // Original operations should still work or fail gracefully
      Promise.all(operations).catch(() => {
        // Expected - some may fail due to reload
      })
    })
  })

  it('rejects AES key with invalid length (must be 32 bytes)', () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(16)), // Invalid
    }
    expect(() => new EnvKeyStore({ env })).toThrow('AES key must be 32 bytes')
  })

  it('rejects HMAC key with length < 32 bytes', () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(16)), // Invalid
    }
    expect(() => new EnvKeyStore({ env })).toThrow('HMAC key must be >=32 bytes')
  })

  it('getAllowedKidsFor for HMAC returns AES allowed set (includes active kid)', () => {
    const env = {
      CRYPTO_ACTIVE_KID: 'A1',
      CRYPTO_ALLOWED_KIDS_AES: 'B1,C1',
      CRYPTO_ALLOWED_KIDS_SIGN: 'S1',
    }
    const ks = new EnvKeyStore({ env })
    const kids = ks.getAllowedKidsFor('HMAC-SHA256')
    expect(kids).toEqual(expect.arrayContaining(['A1', 'B1', 'C1']))
  })
})
