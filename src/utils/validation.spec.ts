import { CryptoErrorCode } from '../errors/crypto.error'

import {
  assertBase64Url,
  assertLength,
  assertMinLength,
  assertMaxSize,
  isEnvelopeV1,
  isSignatureV1,
  isHmacV1,
} from './validation'

describe('utils/validation', () => {
  it('assertBase64Url accepts valid and rejects invalid', () => {
    expect(() => assertBase64Url('x', 'AQID-_')).not.toThrow()
    expect(() => assertBase64Url('x', 'AQID+=')).toThrow()
  })

  it('assertBase64Url handles empty string', () => {
    expect(() => assertBase64Url('empty', '')).not.toThrow()
  })

  it('assertLength enforces exact length', () => {
    expect(() => assertLength('buf', new Uint8Array([1, 2, 3]), 3)).not.toThrow()
    expect(() => assertLength('buf', new Uint8Array([1, 2]), 3)).toThrow()
  })

  it('assertMinLength enforces minimum', () => {
    expect(() => assertMinLength('buf', new Uint8Array([1, 2, 3]), 2)).not.toThrow()
    expect(() => assertMinLength('buf', new Uint8Array([1]), 2)).toThrow()
  })

  it('assertMaxSize enforces maximum', () => {
    expect(() => assertMaxSize('buf', new Uint8Array([1, 2, 3]), 5)).not.toThrow()
    expect(() => assertMaxSize('buf', new Uint8Array([1, 2, 3]), 2)).toThrow()
  })

  it('assertMaxSize throws SIZE_LIMIT_EXCEEDED', () => {
    try {
      assertMaxSize('test', new Uint8Array(100), 50)
      fail('Should have thrown')
    } catch (error) {
      expect(error.code).toBe(CryptoErrorCode.SIZE_LIMIT_EXCEEDED)
      expect(error.message).toContain('exceeds maximum size')
    }
  })

  it('assertMaxSize handles boundary conditions', () => {
    const exactSize = new Uint8Array(100)
    expect(() => assertMaxSize('test', exactSize, 100)).not.toThrow()
    expect(() => assertMaxSize('test', exactSize, 99)).toThrow()
    expect(() => assertMaxSize('test', new Uint8Array(0), 0)).not.toThrow()
  })

  describe('Type Guards', () => {
    it('isEnvelopeV1 validates correct envelope', () => {
      const valid = {
        v: '1',
        alg: 'AES-256-GCM',
        kid: 'K1',
        iv: 'abc',
        tag: 'def',
        ciphertext: 'ghi',
      }
      expect(isEnvelopeV1(valid)).toBe(true)
    })

    it('isEnvelopeV1 validates envelope with AAD', () => {
      const valid = {
        v: '1',
        alg: 'AES-256-GCM',
        kid: 'K1',
        iv: 'abc',
        tag: 'def',
        ciphertext: 'ghi',
        aad: 'jkl',
      }
      expect(isEnvelopeV1(valid)).toBe(true)
    })

    it('isEnvelopeV1 rejects invalid envelopes', () => {
      expect(isEnvelopeV1(null)).toBe(false)
      expect(isEnvelopeV1('string')).toBe(false)
      expect(isEnvelopeV1(123)).toBe(false)
      expect(isEnvelopeV1({})).toBe(false)
      expect(isEnvelopeV1({ v: '2' })).toBe(false)
      expect(isEnvelopeV1({ v: '1', alg: 'wrong' })).toBe(false)
      expect(isEnvelopeV1({ v: '1', alg: 'AES-256-GCM', kid: 123 })).toBe(false)
    })

    it('isSignatureV1 validates correct signature', () => {
      const valid = { v: '1', alg: 'Ed25519', kid: 'K1', sig: 'abc' }
      expect(isSignatureV1(valid)).toBe(true)
    })

    it('isSignatureV1 validates all supported algorithms', () => {
      expect(isSignatureV1({ v: '1', alg: 'Ed25519', kid: 'K1', sig: 'x' })).toBe(true)
      expect(isSignatureV1({ v: '1', alg: 'RSA-PSS-SHA256', kid: 'K1', sig: 'x' })).toBe(
        true,
      )
      expect(isSignatureV1({ v: '1', alg: 'P-256', kid: 'K1', sig: 'x' })).toBe(true)
    })

    it('isSignatureV1 rejects invalid signatures', () => {
      expect(isSignatureV1(null)).toBe(false)
      expect(isSignatureV1({})).toBe(false)
      expect(isSignatureV1({ v: '1', alg: 'wrong', kid: 'K1', sig: 'x' })).toBe(false)
      expect(isSignatureV1({ v: '1', alg: 'Ed25519', kid: 123, sig: 'x' })).toBe(false)
    })

    it('isHmacV1 validates correct HMAC', () => {
      const valid = { v: '1', alg: 'HMAC-SHA256', kid: 'K1', mac: 'abc' }
      expect(isHmacV1(valid)).toBe(true)
    })

    it('isHmacV1 rejects invalid HMACs', () => {
      expect(isHmacV1(null)).toBe(false)
      expect(isHmacV1({})).toBe(false)
      expect(isHmacV1({ v: '1', alg: 'wrong', kid: 'K1', mac: 'x' })).toBe(false)
      expect(isHmacV1({ v: '1', alg: 'HMAC-SHA256', kid: 'K1' })).toBe(false)
    })
  })
})
