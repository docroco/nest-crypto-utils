import { Buffer } from 'node:buffer'

import { CryptoErrorCode } from '../errors/crypto.error'

import {
  toUtf8Bytes,
  fromUtf8Bytes,
  fromUtf8BytesStrict,
  base64UrlEncode,
  base64UrlDecode,
} from './encoding'

describe('encoding utilities', () => {
  describe('toUtf8Bytes', () => {
    it('converts empty string', () => {
      const result = toUtf8Bytes('')
      expect(result).toBeInstanceOf(Uint8Array)
      expect(result.length).toBe(0)
    })

    it('converts ASCII string', () => {
      const result = toUtf8Bytes('hello')
      expect([...result]).toEqual([104, 101, 108, 108, 111])
    })

    it('converts Unicode string', () => {
      const result = toUtf8Bytes('café')
      expect(result.length).toBeGreaterThan(4) // É is multi-byte
    })

    it('converts emoji', () => {
      const result = toUtf8Bytes('🔐')
      expect(result.length).toBe(4) // Emoji is 4 bytes
    })

    it('converts surrogate pairs correctly', () => {
      const result = toUtf8Bytes('𝕳𝖊𝖑𝖑𝖔')
      expect(result.length).toBeGreaterThan(5)
    })
  })

  describe('fromUtf8Bytes', () => {
    it('converts empty byte array', () => {
      const result = fromUtf8Bytes(new Uint8Array(0))
      expect(result).toBe('')
    })

    it('converts valid UTF-8 bytes', () => {
      const bytes = new Uint8Array([104, 101, 108, 108, 111])
      const result = fromUtf8Bytes(bytes)
      expect(result).toBe('hello')
    })

    it('handles invalid UTF-8 with replacement', () => {
      const invalidBytes = new Uint8Array([0xff, 0xfe, 0xfd])
      const result = fromUtf8Bytes(invalidBytes)
      expect(result).toBeDefined()
      expect(result).toContain('\uFFFD') // Replacement character
    })

    it('round-trip encodes and decodes', () => {
      const original = 'Hello 世界 🌟'
      const bytes = toUtf8Bytes(original)
      const result = fromUtf8Bytes(bytes)
      expect(result).toBe(original)
    })
  })

  describe('fromUtf8BytesStrict', () => {
    it('converts valid UTF-8 bytes', () => {
      const bytes = new Uint8Array([104, 101, 108, 108, 111])
      const result = fromUtf8BytesStrict(bytes)
      expect(result).toBe('hello')
    })

    it('throws on invalid UTF-8 bytes', () => {
      const invalidBytes = new Uint8Array([0xff, 0xfe, 0xfd])
      expect(() => fromUtf8BytesStrict(invalidBytes)).toThrow()
    })

    it('round-trip encodes and decodes strictly', () => {
      const original = 'Hello 世界 🌟'
      const bytes = toUtf8Bytes(original)
      const result = fromUtf8BytesStrict(bytes)
      expect(result).toBe(original)
    })
  })

  describe('base64UrlEncode', () => {
    it('encodes empty byte array', () => {
      const result = base64UrlEncode(new Uint8Array(0))
      expect(result).toBe('')
    })

    it('encodes single byte', () => {
      const result = base64UrlEncode(new Uint8Array([65]))
      expect(result).toBe('QQ')
    })

    it('removes padding', () => {
      const bytes = new Uint8Array([1, 2, 3])
      const result = base64UrlEncode(bytes)
      expect(result).not.toContain('=')
    })

    it('uses URL-safe characters', () => {
      const bytes = Buffer.from([0xff, 0xff, 0xff])
      const result = base64UrlEncode(bytes)
      expect(result).not.toContain('+')
      expect(result).not.toContain('/')
      expect(result).toContain('_') // Should use URL-safe chars
    })

    it('encodes all byte values correctly', () => {
      const allBytes = new Uint8Array(256)
      for (let i = 0; i < 256; i++) {
        allBytes[i] = i
      }
      const result = base64UrlEncode(allBytes)
      expect(result).toBeDefined()
      expect(result.length).toBeGreaterThan(0)
      expect(/^[\w-]*$/.test(result)).toBe(true)
    })
  })

  describe('base64UrlDecode', () => {
    it('decodes empty string', () => {
      const result = base64UrlDecode('')
      expect(result).toBeInstanceOf(Uint8Array)
      expect(result.length).toBe(0)
    })

    it('decodes valid base64url', () => {
      const result = base64UrlDecode('AQID')
      expect([...result]).toEqual([1, 2, 3])
    })

    it('handles URL-safe characters', () => {
      const result = base64UrlDecode('_-8')
      expect(result).toBeInstanceOf(Uint8Array)
    })

    it('adds padding correctly', () => {
      // Base64url without padding
      const result = base64UrlDecode('QQ')
      expect([...result]).toEqual([65])
    })

    it('throws on invalid characters', () => {
      expect(() => base64UrlDecode('ABC+DEF')).toThrow()
      expect(() => base64UrlDecode('ABC/DEF')).toThrow()
      expect(() => base64UrlDecode('ABC=DEF')).toThrow()
    })

    it('throws on invalid base64 structure', () => {
      expect(() => base64UrlDecode('!!!!')).toThrow()
    })

    it('throws CryptoError with ENCODING_ERROR code', () => {
      try {
        base64UrlDecode('ABC+DEF')
        fail('Should have thrown')
      } catch (error) {
        expect(error.code).toBe(CryptoErrorCode.ENCODING_ERROR)
      }
    })

    it('round-trip encodes and decodes', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
      const encoded = base64UrlEncode(original)
      const decoded = base64UrlDecode(encoded)
      expect(Buffer.from(decoded)).toEqual(Buffer.from(original))
    })

    it('handles various padding scenarios', () => {
      // Length % 4 === 0 (no padding needed)
      expect(() => base64UrlDecode('AQIDBA')).not.toThrow()
      
      // Length % 4 === 2 (needs 2 padding)
      expect(() => base64UrlDecode('QQ')).not.toThrow()
      
      // Length % 4 === 3 (needs 1 padding)
      expect(() => base64UrlDecode('QQE')).not.toThrow()
    })
  })
})

