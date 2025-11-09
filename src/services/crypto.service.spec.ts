import { Buffer } from 'node:buffer'
import { hkdfSync } from 'node:crypto'

import { CryptoErrorCode } from '../errors/crypto.error'
import { EnvKeyStore } from '../keystore/env-key-store'
import { base64UrlEncode, base64UrlDecode } from '../utils/encoding'

import { CryptoService } from './crypto.service'

import type { SymmetricAlg } from '../types/alg'
import type { EnvelopeV1 } from '../types/envelope'
import type { Logger } from '@nestjs/common'

function withEnv<T>(vars: Record<string, string>, fn: () => T): T {
  const old = { ...process.env }
  Object.assign(process.env, vars)
  try {
    return fn()
  } finally {
    process.env = old
  }
}

describe('CryptoService (AES-GCM, HMAC, KDFs)', () => {
  it('encrypts and decrypts with AAD', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 7)
    const hmacKey = Buffer.alloc(32, 9)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const aad = 'meta'
      const envelope = await svc.encrypt('hello', { aad })
      expect(envelope.alg).toBe('AES-256-GCM')
      const pt = await svc.decrypt(envelope, { aad })
      expect(Buffer.from(pt).toString('utf8')).toBe('hello')
    })
  })

  it('decryptToString default utf8 works', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 7)
    const hmacKey = Buffer.alloc(32, 9)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const envelope = await svc.encrypt('hello')
      const text = await svc.decryptToString(envelope)
      expect(text).toBe('hello')
    })
  })

  it('decryptToString supports base64, base64url and hex', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 3)
    const hmacKey = Buffer.alloc(32, 4)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const payload = new TextEncoder().encode('xyz')
      const envelope = await svc.encrypt(payload)
      const b64 = await svc.decryptToString(envelope, { encoding: 'base64' })
      const b64u = await svc.decryptToString(envelope, { encoding: 'base64url' })
      const hex = await svc.decryptToString(envelope, { encoding: 'hex' })
      expect(b64).toBe(Buffer.from(payload).toString('base64'))
      expect(b64u).toBe(base64UrlEncode(payload))
      expect(hex).toBe(Buffer.from(payload).toString('hex'))
    })
  })

  it('rejects tampered ciphertext', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const hmacKey = Buffer.alloc(32, 2)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const envelope = await svc.encrypt('secret')
      // Tamper a byte in ciphertext
      const ct = Buffer.from(base64UrlDecode(envelope.ciphertext))
      ct[0] ^= 0xff
      envelope.ciphertext = base64UrlEncode(ct)
      await expect(svc.decrypt(envelope)).rejects.toMatchObject({
        code: CryptoErrorCode.DECRYPT_AUTH_FAILED,
      })
    })
  })

  it('rejects on AAD mismatch explicitly', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const hmacKey = Buffer.alloc(32, 2)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const envelope = await svc.encrypt('secret', { aad: 'meta' })
      await expect(svc.decrypt(envelope, { aad: 'other' })).rejects.toMatchObject({
        code: CryptoErrorCode.DECRYPT_AUTH_FAILED,
      })
    })
  })

  it('rejects on AAD mismatch when lengths match', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const hmacKey = Buffer.alloc(32, 2)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const envelope = await svc.encrypt('secret', { aad: 'meta' })
      await expect(svc.decrypt(envelope, { aad: 'teta' })).rejects.toMatchObject({
        code: CryptoErrorCode.DECRYPT_AUTH_FAILED,
      })
    })
  })

  it('produces HMAC-SHA256 of expected length', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 3)
    const hmacKey = Buffer.alloc(32, 4)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const mac = await svc.hmac('abc')
      const macBytes = base64UrlDecode(mac.mac)
      expect(macBytes).toHaveLength(32)
    })
  })

  it('rejects unsupported HMAC algorithms', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 3)
    const hmacKey = Buffer.alloc(32, 4)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      await expect(
        svc.hmac('data', { alg: 'HMAC-SHA1' as unknown as 'HMAC-SHA256' }),
      ).rejects.toMatchObject({ code: CryptoErrorCode.UNSUPPORTED_ALG })
    })
  })

  it('derives keys with PBKDF2/HKDF of correct length', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 5)
    const hmacKey = Buffer.alloc(32, 6)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const pb = await svc.deriveKeyPBKDF2('pw', {
        salt: 'salt',
        iterations: 1000,
        length: 32,
      })
      expect(pb.length).toBe(32)
      const hk = await svc.deriveKeyHKDF('ikm', {
        salt: 'salt',
        info: 'info',
        length: 32,
      })
      expect(hk.length).toBe(32)
      const expected = hkdfSync(
        'sha256',
        Buffer.from('ikm'),
        Buffer.from('salt'),
        Buffer.from('info'),
        32,
      )
      const expectedBytes = new Uint8Array(expected)
      expect(hk).toEqual(expectedBytes)
    })
  })

  it('rejects invalid envelope version and alg', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const hmacKey = Buffer.alloc(32, 2)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const good = await svc.encrypt('x')
      const badV = { ...good, v: '9' }
      const badAlg = { ...good, alg: 'AES-128-GCM' }
      await expect(svc.decrypt(badV as unknown as EnvelopeV1)).rejects.toMatchObject({
        code: CryptoErrorCode.INVALID_ENVELOPE,
      })
      await expect(svc.decrypt(badAlg as unknown as EnvelopeV1)).rejects.toMatchObject({
        code: CryptoErrorCode.INVALID_ENVELOPE,
      })
    })
  })

  it('encryptToString canonical ordering is stable', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 7)
    const hmacKey = Buffer.alloc(32, 9)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const s1 = await svc.encryptToString('hello', { canonical: true })
      const s2 = await svc.encryptToString('hello', { canonical: true })
      // Nonce differs; stable ordering still ensures consistent key order, but string differs overall.
      // Validate ordering by parsing and checking keys order indirectly by JSON.stringify with same structure
      const j1 = JSON.parse(s1)
      const j2 = JSON.parse(s2)
      expect(Object.keys(j1)).toEqual(['v', 'alg', 'kid', 'iv', 'tag', 'ciphertext'])
      expect(Object.keys(j2)).toEqual(['v', 'alg', 'kid', 'iv', 'tag', 'ciphertext'])
    })
  })

  it('encryptToString returns envelope JSON when canonical is false', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 7)
    const hmacKey = Buffer.alloc(32, 9)
    const envVars = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }
    await withEnv(envVars, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const json = await svc.encryptToString('data')
      const parsed = JSON.parse(json)
      expect(parsed).toMatchObject({
        v: '1',
        alg: 'AES-256-GCM',
        kid,
      })
    })
  })

  it('decryptFromString rejects invalid JSON or shape', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 7)
    const hmacKey = Buffer.alloc(32, 9)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      await expect(svc.decryptFromString('{not json')).rejects.toBeDefined()
      await expect(
        svc.decryptFromString(
          JSON.stringify({ v: '1', alg: 'AES-256-GCM', kid, iv: 'x', tag: 'y' }),
        ),
      ).rejects.toBeDefined()
    })
  })

  it('decryptToString strictUtf8 enforces valid UTF-8', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 7)
    const hmacKey = Buffer.alloc(32, 9)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const bad = new Uint8Array([0xff, 0xfe, 0xfd])
      const envl = await svc.encrypt(bad)
      await expect(
        svc.decryptToString(envl, { encoding: 'utf8', strictUtf8: true }),
      ).rejects.toBeDefined()
      await expect(
        svc.decryptToString(envl, { encoding: 'utf8', strictUtf8: false }),
      ).resolves.toBeDefined()
    })
  })

  it('decryptToString falls back to UTF-8 for unknown encoding', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 7)
    const hmacKey = Buffer.alloc(32, 9)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const envelope = await svc.encrypt('payload')
      const out = await svc.decryptToString(envelope, {
        encoding: 'unknown' as unknown as 'utf8',
      })
      expect(out).toBe('payload')
    })
  })

  it('timingSafeEqual behaves as expected', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 7)
    const hmacKey = Buffer.alloc(32, 9)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      expect(svc.timingSafeEqual('abc', 'abc')).toBe(true)
      expect(svc.timingSafeEqual('abc', 'abd')).toBe(false)
      expect(svc.timingSafeEqual('abc', 'abcd')).toBe(false)
    })
  })

  it('timingSafeEqual handles empty inputs', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 7)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      // Test empty strings
      expect(svc.timingSafeEqual('', '')).toBe(true)
      expect(svc.timingSafeEqual('', 'a')).toBe(false)
      // Test empty Uint8Arrays
      expect(svc.timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true)
      expect(svc.timingSafeEqual(new Uint8Array(0), new Uint8Array([1]))).toBe(false)
    })
  })

  it('deriveKeyPBKDF2 handles edge cases', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 5)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})

      // Very low iterations (edge case but technically valid)
      const lowIter = await svc.deriveKeyPBKDF2('password', {
        salt: 'salt',
        iterations: 1,
        length: 32,
      })
      expect(lowIter.length).toBe(32)

      // Empty salt (valid edge case)
      const emptySalt = await svc.deriveKeyPBKDF2('password', {
        salt: '',
        iterations: 1000,
        length: 32,
      })
      expect(emptySalt.length).toBe(32)

      // Short derived key
      const shortKey = await svc.deriveKeyPBKDF2('password', {
        salt: 'salt',
        iterations: 1000,
        length: 16,
      })
      expect(shortKey.length).toBe(16)
    })
  })

  it('deriveKeyHKDF handles edge cases', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 5)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})

      // Empty info
      const emptyInfo = await svc.deriveKeyHKDF('ikm', {
        salt: 'salt',
        info: '',
        length: 32,
      })
      expect(emptyInfo.length).toBe(32)

      // Omitted info (uses default empty)
      const noInfo = await svc.deriveKeyHKDF('ikm', { salt: 'salt', length: 32 })
      expect(noInfo.length).toBe(32)
    })
  })

  it('rejects encryption input exceeding maxEncryptionInputSize', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const hmacKey = Buffer.alloc(32, 2)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, { maxEncryptionInputSize: 100 })
      const largeInput = Buffer.alloc(200)
      await expect(svc.encrypt(largeInput)).rejects.toMatchObject({
        code: CryptoErrorCode.SIZE_LIMIT_EXCEEDED,
      })
    })
  })

  it('rejects decryption ciphertext exceeding maxEncryptionInputSize', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const hmacKey = Buffer.alloc(32, 2)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      // Create envelope with large ciphertext
      const svc1 = new CryptoService(ks, {})
      const envelope = await svc1.encrypt(Buffer.alloc(200))
      // Try to decrypt with smaller limit
      const svc2 = new CryptoService(ks, { maxEncryptionInputSize: 100 })
      await expect(svc2.decrypt(envelope)).rejects.toMatchObject({
        code: CryptoErrorCode.SIZE_LIMIT_EXCEEDED,
      })
    })
  })

  it('rejects HMAC input exceeding maxHmacInputSize', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 3)
    const hmacKey = Buffer.alloc(32, 4)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, { maxHmacInputSize: 100 })
      const largeInput = Buffer.alloc(200)
      await expect(svc.hmac(largeInput)).rejects.toMatchObject({
        code: CryptoErrorCode.SIZE_LIMIT_EXCEEDED,
      })
    })
  })
})

describe('CryptoService error handling', () => {
  it('throws UNSUPPORTED_ALG for invalid symmetric algorithm', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      await expect(
        svc.encrypt('test', { alg: 'AES-128-GCM' as unknown as SymmetricAlg }),
      ).rejects.toMatchObject({
        code: CryptoErrorCode.UNSUPPORTED_ALG,
      })
    })
  })

  it('handles empty string encryption', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const envelope = await svc.encrypt('')
      const pt = await svc.decryptToString(envelope)
      expect(pt).toBe('')
    })
  })

  it('handles empty Uint8Array encryption', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const envelope = await svc.encrypt(new Uint8Array(0))
      const pt = await svc.decrypt(envelope)
      expect(pt.length).toBe(0)
    })
  })

  it('handles plaintext at exact size limit boundary', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const maxSize = 1000
      const svc = new CryptoService(ks, { maxEncryptionInputSize: maxSize })
      const exactSize = Buffer.alloc(maxSize, 0xff)
      const envelope = await svc.encrypt(exactSize)
      expect(envelope.ciphertext).toBeDefined()
    })
  })

  it('throws INVALID_ENVELOPE for missing required fields', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const badEnvelope = {
        v: '1',
        alg: 'AES-256-GCM',
        kid: 'K1',
        iv: 'test',
        // Missing tag and ciphertext
      }
      await expect(
        svc.decrypt(badEnvelope as unknown as EnvelopeV1),
      ).rejects.toBeDefined()
    })
  })

  it('throws INVALID_ENVELOPE for wrong version', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const envelope = await svc.encrypt('test')
      const badEnvelope = { ...envelope, v: '2' }
      await expect(
        svc.decrypt(badEnvelope as unknown as EnvelopeV1),
      ).rejects.toMatchObject({
        code: CryptoErrorCode.INVALID_ENVELOPE,
      })
    })
  })

  it('logs debug information when decryption fails (with mock logger)', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const mockLogger = {
        debug: jest.fn(),
      }
      const svc = new CryptoService(ks, {}, mockLogger as unknown as Logger)
      const envelope = await svc.encrypt('test')
      // Tamper with ciphertext
      const ct = Buffer.from(base64UrlDecode(envelope.ciphertext))
      ct[0] ^= 0xff
      envelope.ciphertext = base64UrlEncode(ct)

      await expect(svc.decrypt(envelope)).rejects.toBeDefined()
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'Decryption failed',
        expect.objectContaining({
          kid: 'K1',
          hasAAD: false,
          providedAAD: false,
        }),
      )
    })
  })
})

describe('CryptoService edge cases', () => {
  it('encrypts and decrypts binary data with all byte values', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const allBytes = new Uint8Array(256)
      for (let i = 0; i < 256; i++) {
        allBytes[i] = i
      }
      const envelope = await svc.encrypt(allBytes)
      const pt = await svc.decrypt(envelope)
      expect(Buffer.from(pt)).toEqual(Buffer.from(allBytes))
    })
  })

  it('handles Unicode characters in plaintext', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const unicode = '🔐 Hello 世界 🌟 مرحبا'
      const envelope = await svc.encrypt(unicode)
      const pt = await svc.decryptToString(envelope)
      expect(pt).toBe(unicode)
    })
  })

  it('handles very long AAD strings', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const longAad = 'x'.repeat(10_000)
      const envelope = await svc.encrypt('test', { aad: longAad })
      const pt = await svc.decryptToString(envelope, { aad: longAad })
      expect(pt).toBe('test')
    })
  })

  it('handles AAD with special characters', async () => {
    const kid = 'K1'
    const aesKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_AES_KEY_${kid}`]: base64UrlEncode(aesKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const specialAad = '{"user":"test@example.com","session":"abc-123"}'
      const envelope = await svc.encrypt('data', { aad: specialAad })
      const pt = await svc.decryptToString(envelope, { aad: specialAad })
      expect(pt).toBe('data')
    })
  })

  it('HMAC handles empty input', async () => {
    const kid = 'K1'
    const hmacKey = Buffer.alloc(32, 1)
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_HMAC_KEY_${kid}`]: base64UrlEncode(hmacKey),
    }
    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new CryptoService(ks, {})
      const mac = await svc.hmac('')
      expect(mac.mac).toBeDefined()
      expect(mac.mac.length).toBeGreaterThan(0)
    })
  })
})
