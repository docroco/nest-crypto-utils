import { generateKeyPairSync } from 'node:crypto'

import { InMemoryKeyStore } from './in-memory-key-store'

describe('InMemoryKeyStore', () => {
  it('setters populate keys and lookups succeed', () => {
    const ks = new InMemoryKeyStore({ activeKid: 'K1' })
    ks.setSymmetricKey('K1', new Uint8Array(32))
    ks.setHmacKey('K1', new Uint8Array(32))
    expect(ks.getActiveKidFor('AES-256-GCM')).toBe('K1')
    expect(ks.getAllowedKidsFor('AES-256-GCM')).toContain('K1')
  })

  it('throws on invalid lengths and missing keys', () => {
    const ks = new InMemoryKeyStore({ activeKid: 'K1' })
    expect(() => ks.setSymmetricKey('K1', new Uint8Array(16))).toThrow()
    expect(() => ks.setHmacKey('K1', new Uint8Array(16))).toThrow()
    expect(() => ks.getSymmetricKey('AES-256-GCM', 'missing')).toThrow()
    expect(() => ks.getHmacKey('HMAC-SHA256', 'missing')).toThrow()
    expect(() => ks.getPrivateKey('Ed25519', 'missing')).toThrow()
    expect(() => ks.getPublicKey('Ed25519', 'missing')).toThrow()
  })

  it('getAllowedKidsFor for HMAC returns AES set', () => {
    const ks = new InMemoryKeyStore({ activeKid: 'K1' })
    ks.setSymmetricKey('K1', new Uint8Array(32))
    expect(ks.getAllowedKidsFor('HMAC-SHA256')).toContain('K1')
  })

  it('setP256Keys stores and retrieves P-256 keys', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    })
    const ks = new InMemoryKeyStore({ activeKid: 'K1' })
    const privPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
    const pubPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()

    ks.setP256Keys('K1', privPem, pubPem)

    const priv = ks.getPrivateKey('P-256', 'K1')
    const pub = ks.getPublicKey('P-256', 'K1')
    expect(priv).toBeDefined()
    expect(pub).toBeDefined()
  })

  it('setActiveKid changes active kid', () => {
    const ks = new InMemoryKeyStore({ activeKid: 'K1' })
    expect(ks.getActiveKidFor('AES-256-GCM')).toBe('K1')

    ks.setActiveKid('K2')
    expect(ks.getActiveKidFor('AES-256-GCM')).toBe('K2')
  })

  it('multiple key types coexist', () => {
    const { privateKey: ed25519Priv, publicKey: ed25519Pub } =
      generateKeyPairSync('ed25519')
    const { privateKey: rsaPriv, publicKey: rsaPub } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
    })
    const { privateKey: p256Priv, publicKey: p256Pub } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    })

    const ks = new InMemoryKeyStore({ activeKid: 'K1' })
    ks.setSymmetricKey('K1', new Uint8Array(32))
    ks.setHmacKey('K1', new Uint8Array(32))
    ks.setEd25519Keys(
      'K1',
      ed25519Priv.export({ format: 'pem', type: 'pkcs8' }).toString(),
      ed25519Pub.export({ format: 'pem', type: 'spki' }).toString(),
    )
    ks.setRsaPssKeys(
      'K1',
      rsaPriv.export({ format: 'pem', type: 'pkcs8' }).toString(),
      rsaPub.export({ format: 'pem', type: 'spki' }).toString(),
    )
    ks.setP256Keys(
      'K1',
      p256Priv.export({ format: 'pem', type: 'pkcs8' }).toString(),
      p256Pub.export({ format: 'pem', type: 'spki' }).toString(),
    )

    expect(ks.getSymmetricKey('AES-256-GCM', 'K1')).toBeDefined()
    expect(ks.getHmacKey('HMAC-SHA256', 'K1')).toBeDefined()
    expect(ks.getPrivateKey('Ed25519', 'K1')).toBeDefined()
    expect(ks.getPrivateKey('RSA-PSS-SHA256', 'K1')).toBeDefined()
    expect(ks.getPrivateKey('P-256', 'K1')).toBeDefined()
  })

  it('overwriting existing keys works', () => {
    const ks = new InMemoryKeyStore({ activeKid: 'K1' })
    const key1 = new Uint8Array(32).fill(1)
    const key2 = new Uint8Array(32).fill(2)

    ks.setSymmetricKey('K1', key1)
    const first = ks.getSymmetricKey('AES-256-GCM', 'K1')
    expect(first).toBeDefined()

    ks.setSymmetricKey('K1', key2)
    const second = ks.getSymmetricKey('AES-256-GCM', 'K1')
    expect(second).toBeDefined()

    expect(first).not.toBe(second)
  })
})
