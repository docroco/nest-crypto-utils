import { Buffer } from 'node:buffer'

import { EnvKeyStore } from '../keystore/env-key-store'
import { base64UrlEncode } from '../utils/encoding'

import { CryptoStreamService } from './crypto-stream.service'

function withEnv<T>(vars: Record<string, string>, fn: () => T): T {
  const old = { ...process.env }
  Object.assign(process.env, vars)
  try {
    return fn()
  } finally {
    process.env = old
  }
}

describe('CryptoStreamService', () => {
  it('encrypts/decrypts with AAD', () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 1)),
    }
    withEnv(env, () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoStreamService(ks)
      const { meta, cipher } = svc.createEncryptStream({ aad: 'ctx' })
      const pt = Buffer.from('hello')
      const ct = Buffer.concat([cipher.update(pt), cipher.final()])
      const { tag } = svc.finalizeEncryptStream(meta, cipher)
      const decipher = svc.createDecryptStream({ ...meta, tag })
      const out = Buffer.concat([decipher.update(ct), decipher.final()])
      expect(out.toString('utf8')).toBe('hello')
    })
  })

  it('multi-chunk encrypt/decrypt and wrong tag/AAD handling', () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 2)),
    }
    withEnv(env, () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoStreamService(ks)
      const { meta, cipher } = svc.createEncryptStream({ aad: 'ctx' })
      const chunks = [Buffer.from('hel'), Buffer.from('lo '), Buffer.from('world')]
      const ct = Buffer.concat([
        cipher.update(chunks[0]),
        cipher.update(chunks[1]),
        cipher.update(chunks[2]),
        cipher.final(),
      ])
      const { tag } = svc.finalizeEncryptStream(meta, cipher)
      const decipher = svc.createDecryptStream({ ...meta, tag })
      const out = Buffer.concat([decipher.update(ct), decipher.final()])
      expect(out.toString('utf8')).toBe('hello world')

      // Wrong tag
      expect(() =>
        svc.createDecryptStream({ ...meta, tag: base64UrlEncode(Buffer.from('wrong')) }),
      ).toBeDefined()
      const dec2 = svc.createDecryptStream({ ...meta, tag })
      expect(() => dec2.setAuthTag(Buffer.from(Buffer.alloc(16)))).toThrow()

      // Wrong AAD
      const dec3 = svc.createDecryptStream({ ...meta, tag })
      dec3.setAAD(Buffer.from('wrong'))
      expect(() => Buffer.concat([dec3.update(ct), dec3.final()])).toThrow()
    })
  })

  it('encrypts/decrypts without AAD', () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 5)),
    }
    withEnv(env, () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoStreamService(ks)
      const { meta, cipher } = svc.createEncryptStream()
      const pt = Buffer.from('no aad')
      const ct = Buffer.concat([cipher.update(pt), cipher.final()])
      const { tag } = svc.finalizeEncryptStream(meta, cipher)
      const dec = svc.createDecryptStream({ ...meta, tag })
      const out = Buffer.concat([dec.update(ct), dec.final()])
      expect(out.toString('utf8')).toBe('no aad')
    })
  })

  it('supports Uint8Array AAD inputs', () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 6)),
    }
    withEnv(env, () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoStreamService(ks)
      const aad = new Uint8Array([1, 2, 3, 4])
      const { meta, cipher } = svc.createEncryptStream({ aad })
      const ct = Buffer.concat([cipher.update('hi'), cipher.final()])
      const { tag } = svc.finalizeEncryptStream(meta, cipher)
      const decipher = svc.createDecryptStream({ ...meta, tag })
      const out = Buffer.concat([decipher.update(ct), decipher.final()])
      expect(out.toString('utf8')).toBe('hi')
    })
  })

  it('HMAC streaming determinism', () => {
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 3)),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(Buffer.alloc(32, 4)),
    }
    withEnv(env, () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoStreamService(ks)
      const a1 = svc.hmacStream()
      const a2 = svc.hmacStream()
      const msg = Buffer.from('payload')
      a1.transform.write(msg)
      a1.transform.end()
      a2.transform.write(msg)
      a2.transform.end()
      const m1 = a1.finalize()
      const m2 = a2.finalize()
      expect(m1.mac).toBe(m2.mac)
      const b = svc.hmacStream()
      b.transform.write(Buffer.from('other'))
      b.transform.end()
      const m3 = b.finalize()
      expect(m3.mac).not.toBe(m1.mac)
    })
  })
})
