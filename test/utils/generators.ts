import { Buffer } from 'node:buffer'
import { generateKeyPairSync } from 'node:crypto'

import { CryptoError, CryptoErrorCode } from '../../src/errors/crypto.error'
import { base64UrlEncode } from '../../src/utils/encoding'

import type { SignAlg } from '../../src/types/alg'
import type { EnvelopeV1, HmacV1, SignatureV1 } from '../../src/types/envelope'
import type { KeyObject } from 'node:crypto'

/**
 * Generate a valid test envelope with optional overrides.
 * @param overrides Partial envelope to merge with defaults
 * @returns A valid EnvelopeV1 for testing
 */
export function generateTestEnvelope(overrides?: Partial<EnvelopeV1>): EnvelopeV1 {
  const defaults: EnvelopeV1 = {
    v: '1',
    alg: 'AES-256-GCM',
    kid: 'test-kid',
    iv: base64UrlEncode(Buffer.alloc(12, 0xaa)),
    tag: base64UrlEncode(Buffer.alloc(16, 0xbb)),
    ciphertext: base64UrlEncode(Buffer.from('test-ciphertext')),
  }

  return { ...defaults, ...overrides }
}

/**
 * Generate a valid test signature with optional overrides.
 * @param overrides Partial signature to merge with defaults
 * @returns A valid SignatureV1 for testing
 */
export function generateTestSignature(overrides?: Partial<SignatureV1>): SignatureV1 {
  const defaults: SignatureV1 = {
    v: '1',
    alg: 'Ed25519',
    kid: 'test-kid',
    sig: base64UrlEncode(Buffer.alloc(64, 0xcc)),
  }

  return { ...defaults, ...overrides }
}

/**
 * Generate a valid test HMAC with optional overrides.
 * @param overrides Partial HMAC to merge with defaults
 * @returns A valid HmacV1 for testing
 */
export function generateTestHmac(overrides?: Partial<HmacV1>): HmacV1 {
  const defaults: HmacV1 = {
    v: '1',
    alg: 'HMAC-SHA256',
    kid: 'test-kid',
    mac: base64UrlEncode(Buffer.alloc(32, 0xdd)),
  }

  return { ...defaults, ...overrides }
}

/**
 * Generate test key pair for the specified algorithm.
 * @param alg Signing algorithm
 * @returns Key pair with private and public keys
 */
export function generateTestKeys(alg: SignAlg): {
  privateKey: KeyObject
  publicKey: KeyObject
} {
  switch (alg) {
    case 'Ed25519': {
      return generateKeyPairSync('ed25519')
    }
    case 'RSA-PSS-SHA256': {
      return generateKeyPairSync('rsa', { modulusLength: 2048 })
    }
    case 'P-256': {
      return generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    }
    default: {
      throw new CryptoError(
        CryptoErrorCode.UNSUPPORTED_ALG,
        `Unsupported algorithm: ${alg}`,
      )
    }
  }
}

/**
 * Corrupt an envelope for negative testing.
 * @param envelope Valid envelope to corrupt
 * @param field Field to corrupt
 * @param corruption Type of corruption
 * @returns Corrupted envelope
 */
export function corruptEnvelope(
  envelope: EnvelopeV1,
  field: keyof EnvelopeV1,
  corruption: 'delete' | 'modify' | 'wrong-type' | 'invalid-base64url',
): Partial<EnvelopeV1> {
  const corrupted: EnvelopeV1 = { ...envelope }

  switch (corruption) {
    case 'delete': {
      delete corrupted[field]
      break
    }
    case 'modify': {
      if (typeof corrupted[field] === 'string') {
        ;(corrupted as unknown as Record<string, string>)[field] =
          `${(corrupted as unknown as Record<string, string>)[field]}corrupted`
      }
      break
    }
    case 'wrong-type': {
      ;(corrupted as unknown as Record<string, unknown>)[field] = 12_345
      break
    }
    case 'invalid-base64url': {
      if (typeof corrupted[field] === 'string') {
        ;(corrupted as unknown as Record<string, string>)[field] = 'invalid+/base64=='
      }
      break
    }
    default: {
      throw new CryptoError(
        CryptoErrorCode.INVALID_ENVELOPE,
        `Invalid envelope field: ${field}`,
      )
    }
  }

  return corrupted
}

/**
 * Corrupt a signature for negative testing.
 * @param signature Valid signature to corrupt
 * @param field Field to corrupt
 * @param corruption Type of corruption
 * @returns Corrupted signature
 */
export function corruptSignature(
  signature: SignatureV1,
  field: keyof SignatureV1,
  corruption: 'delete' | 'modify' | 'wrong-type',
): Partial<SignatureV1> {
  const corrupted = { ...signature }

  switch (corruption) {
    case 'delete': {
      delete (corrupted as unknown as Record<string, unknown>)[field]
      break
    }
    case 'modify': {
      if (typeof (corrupted as unknown as Record<string, string>)[field] === 'string') {
        ;(corrupted as unknown as Record<string, string>)[field] =
          `${(corrupted as unknown as Record<string, string>)[field]}x`
      }
      break
    }
    case 'wrong-type': {
      ;(corrupted as unknown as Record<string, unknown>)[field] = null
      break
    }
    default: {
      throw new CryptoError(
        CryptoErrorCode.INVALID_SIGNATURE,
        `Invalid signature field: ${field}`,
      )
    }
  }

  return corrupted
}
