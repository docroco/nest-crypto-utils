/* eslint-disable class-methods-use-this -- this is a service class */
import { Buffer } from 'node:buffer'
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
  createHmac,
  pbkdf2,
  hkdf,
} from 'node:crypto'

import { Inject, Injectable, Optional } from '@nestjs/common'

import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'
import { CRYPTO_OPTIONS, KEY_STORE } from '../module/crypto.module'
import { toBytes } from '../utils/bytes'
import {
  base64UrlDecode,
  base64UrlEncode,
  fromUtf8Bytes,
  fromUtf8BytesStrict,
} from '../utils/encoding'
import { assertMaxSize } from '../utils/validation'

import type { CryptoModuleOptions } from '../config/crypto.options'
import type { KeyStore } from '../keystore/key-store'
import type { SymmetricAlg } from '../types/alg'
import type { EnvelopeV1, HmacV1 } from '../types/envelope'
import type { Logger } from '@nestjs/common'

const AES_ALG: SymmetricAlg = 'AES-256-GCM'

/**
 * @summary Symmetric crypto utilities (AES-256-GCM), HMAC-SHA256, and KDFs.
 * @remarks
 * Provides high-level helpers for authenticated encryption/decryption, computing HMACs,
 * and deriving keys using PBKDF2/HKDF, with safe defaults and base64url helpers.
 *
 * ## Security: AES-GCM Nonce Management
 *
 * This service uses **random 96-bit IVs (nonces)** for each AES-GCM encryption operation.
 * While cryptographically secure random generation is used, there are important considerations:
 *
 * ### Nonce Collision Risk
 * - Random nonces have a birthday paradox collision probability
 * - At ~2^48 encryptions with the same key, there's a 50% chance of nonce reuse
 * - **Nonce reuse with AES-GCM is catastrophic** - it completely breaks confidentiality
 *
 * ### Recommendations
 * 1. **Rotate keys regularly** - Use the `kid` mechanism to version keys
 * 2. **Limit encryptions per key** - Rotate before 2^32 operations (conservative limit)
 * 3. **In distributed systems** - Ensure each instance uses unique keys or implement
 *    counter-based nonce generation
 * 4. **Monitor usage** - Track encryption counts per key in production
 *
 * ### Key Rotation Example
 * ```ts
 * // Rotate to new key when approaching limits
 * const envelope = await crypto.encrypt(data, { kid: 'key-v2' })
 * // Old keys remain available for decryption
 * ```
 *
 * For more details, see the Security Considerations section in the README.
 */
@Injectable()
export class CryptoService {
  constructor(
    @Inject(KEY_STORE) private readonly keyStore: KeyStore,
    @Inject(CRYPTO_OPTIONS) private readonly options: CryptoModuleOptions,
    @Optional() private readonly logger?: Logger,
  ) {}

  async encrypt(
    input: string | Uint8Array,
    options?: { aad?: string | Uint8Array; kid?: string; alg?: SymmetricAlg },
  ): Promise<EnvelopeV1> {
    /**
     * @summary Encrypt a string or byte payload using AES-256-GCM.
     * @param input Plaintext as `string | Uint8Array`.
     * @param options Optional AAD, key id, and algorithm (AES-256-GCM only).
     * @returns Envelope containing algorithm, kid, iv, tag, ciphertext, and optional aad.
     * @throws {@link CryptoError} with code `UNSUPPORTED_ALG` when algorithm isn't AES-256-GCM.
     * @example
     * ```ts
     * const env = await crypto.encrypt('hello', { aad: 'ctx' })
     * ```
     */
    const alg = options?.alg ?? AES_ALG
    if (alg !== AES_ALG)
      throw new CryptoError(CryptoErrorCode.UNSUPPORTED_ALG, `Unsupported alg: ${alg}`)
    const kid = options?.kid ?? this.keyStore.getActiveKidFor(alg)
    const key = this.keyStore.getSymmetricKey(alg, kid)

    // Validate input size
    const inputBytes = toBytes(input)
    const maxSize = this.options.maxEncryptionInputSize ?? 10 * 1024 * 1024
    assertMaxSize('plaintext', inputBytes, maxSize)

    // Generate random 96-bit IV (nonce) for GCM mode
    // Note: Random nonces have collision risk at ~2^48 operations per key
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    if (options?.aad) cipher.setAAD(toBytes(options.aad))
    const ct = Buffer.concat([cipher.update(inputBytes), cipher.final()])
    const tag = cipher.getAuthTag()

    return {
      v: '1',
      alg,
      kid,
      iv: base64UrlEncode(iv),
      tag: base64UrlEncode(tag),
      ciphertext: base64UrlEncode(ct),
      aad: options?.aad ? base64UrlEncode(toBytes(options.aad)) : undefined,
    }
  }

  async decrypt(
    envelope: EnvelopeV1,
    options?: { aad?: string | Uint8Array },
  ): Promise<Uint8Array> {
    /**
     * @summary Decrypt an AES-256-GCM envelope.
     * @param envelope Envelope produced by {@link encrypt}.
     * @param options Optional AAD to assert equality with envelope AAD.
     * @returns Decrypted plaintext bytes.
     * @throws {@link CryptoError} with code `INVALID_ENVELOPE` when envelope is invalid.
     * @throws {@link CryptoError} with code `DECRYPT_AUTH_FAILED` when tag validation fails
     * or when provided AAD does not match the envelope.
     */
    if (envelope.v !== '1' || envelope.alg !== AES_ALG) {
      throw new CryptoError(CryptoErrorCode.INVALID_ENVELOPE, 'Invalid envelope')
    }
    const { kid } = envelope
    const key = this.keyStore.getSymmetricKey(AES_ALG, kid)
    const iv = base64UrlDecode(envelope.iv)
    const tag = base64UrlDecode(envelope.tag)
    const ct = base64UrlDecode(envelope.ciphertext)
    const aad = envelope.aad ? base64UrlDecode(envelope.aad) : undefined

    // Validate ciphertext size
    const maxSize = this.options.maxEncryptionInputSize ?? 10 * 1024 * 1024
    assertMaxSize('ciphertext', ct, maxSize + 16) // Allow for GCM tag overhead

    const decipher = createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(Buffer.from(tag))
    if (aad) decipher.setAAD(aad)
    try {
      const pt = Buffer.concat([decipher.update(ct), decipher.final()])
      // Decrypt succeeded. Perform optional AAD equality check outside of catch so
      // we can emit a specific error when the provided AAD does not match.
      if (options?.aad) {
        const provided = toBytes(options.aad)
        const expected = aad ?? new Uint8Array()
        if (provided.length !== expected.length) {
          throw new CryptoError(CryptoErrorCode.DECRYPT_AUTH_FAILED, 'AAD mismatch')
        }
        const pa = Buffer.from(provided)
        const ea = Buffer.from(expected)
        if (!timingSafeEqual(pa, ea)) {
          throw new CryptoError(CryptoErrorCode.DECRYPT_AUTH_FAILED, 'AAD mismatch')
        }
      }
      return new Uint8Array(pt)
    } catch (error) {
      // Log detailed error for debugging while preventing oracle attacks
      this.logger?.debug('Decryption failed', {
        kid: envelope.kid,
        hasAAD: !!envelope.aad,
        providedAAD: !!options?.aad,
        error: error instanceof Error ? error.message : String(error),
      })
      throw new CryptoError(
        CryptoErrorCode.DECRYPT_AUTH_FAILED,
        'Decryption/authentication failed',
      )
    }
  }

  async hmac(
    input: string | Uint8Array,
    options?: { kid?: string; alg?: 'HMAC-SHA256' },
  ): Promise<HmacV1> {
    /**
     * @summary Compute HMAC-SHA256 of input.
     * @param input Message as `string | Uint8Array`.
     * @param options Optional key id and algorithm (HMAC-SHA256 only).
     * @returns HMAC envelope with base64url encoded MAC.
     * @throws {@link CryptoError} with code `UNSUPPORTED_ALG` for other algorithms.
     * @example
     * ```ts
     * const mac = await crypto.hmac('payload')
     * ```
     */
    const alg = options?.alg ?? 'HMAC-SHA256'
    if (alg !== 'HMAC-SHA256')
      throw new CryptoError(
        CryptoErrorCode.UNSUPPORTED_ALG,
        `Unsupported HMAC alg: ${alg}`,
      )
    const kid = options?.kid ?? this.keyStore.getActiveKidFor(alg)
    const key = this.keyStore.getHmacKey('HMAC-SHA256', kid)

    // Validate input size
    const inputBytes = toBytes(input)
    const maxSize = this.options.maxHmacInputSize ?? 10 * 1024 * 1024
    assertMaxSize('HMAC input', inputBytes, maxSize)

    const h = createHmac('sha256', key)
    h.update(inputBytes)
    const mac = h.digest()
    return { v: '1', alg, kid, mac: base64UrlEncode(mac) }
  }

  async deriveKeyPBKDF2(
    password: string | Uint8Array,
    options: { salt?: string | Uint8Array; iterations?: number; length?: number },
  ): Promise<Uint8Array> {
    /**
     * @summary Derive a key using PBKDF2-HMAC-SHA256.
     * @param password Input password or bytes.
     * @param options Salt (generated if absent), iterations (default 310k), length (default 32).
     * @returns Derived key bytes.
     * @throws Error Propagates system errors from `pbkdf2`.
     */
    const salt = options.salt ? toBytes(options.salt) : randomBytes(16)
    const iterations = options.iterations ?? 310_000
    const length = options.length ?? 32
    return new Promise<Uint8Array>((resolve, reject) => {
      pbkdf2(
        Buffer.from(toBytes(password)),
        Buffer.from(salt),
        iterations,
        length,
        'sha256',
        (err, derivedKey) => {
          if (err) reject(err)
          else resolve(new Uint8Array(derivedKey))
        },
      )
    })
  }

  async deriveKeyHKDF(
    ikm: string | Uint8Array,
    options: { salt: string | Uint8Array; info?: string | Uint8Array; length?: number },
  ): Promise<Uint8Array> {
    /**
     * @summary Derive a key using HKDF-SHA256.
     * @param ikm Input keying material as `string | Uint8Array`.
     * @param options Salt (required), optional info/context, and length (default 32).
     * @returns Derived key bytes.
     * @throws Error Propagates system errors from `hkdf`.
     */
    const salt = toBytes(options.salt)
    const info = options.info ? toBytes(options.info) : new Uint8Array()
    const length = options.length ?? 32
    return new Promise<Uint8Array>((resolve, reject) => {
      // Node's hkdf signature: (digest, ikm, salt, info, length, cb)
      hkdf(
        'sha256',
        Buffer.from(toBytes(ikm)),
        Buffer.from(salt),
        Buffer.from(info),
        length,
        (err, derivedKey) => {
          if (err) reject(err)
          else resolve(new Uint8Array(derivedKey))
        },
      )
    })
  }

  timingSafeEqual(a: string | Uint8Array, b: string | Uint8Array): boolean {
    /**
     * @summary Timing-safe equality for equal-length inputs.
     * @param a First input.
     * @param b Second input.
     * @returns True when equal; false when lengths differ or bytes differ.
     */
    const ab = Buffer.from(toBytes(a))
    const bb = Buffer.from(toBytes(b))
    if (ab.length !== bb.length) return false
    return timingSafeEqual(ab, bb)
  }

  async decryptToString(
    envelope: EnvelopeV1,
    options?: {
      aad?: string | Uint8Array
      encoding?: 'utf8' | 'base64' | 'base64url' | 'hex'
      strictUtf8?: boolean
    },
  ): Promise<string> {
    /**
     * @summary Decrypt envelope and encode plaintext to a string.
     * @param envelope Envelope produced by {@link encrypt}.
     * @param options Optional AAD; output encoding (`utf8`|`base64`|`base64url`|`hex`);
     * `strictUtf8` to fail on invalid UTF-8.
     * @returns Decrypted plaintext string.
     */
    const bytes = await this.decrypt(envelope, { aad: options?.aad })
    const enc = options?.encoding ?? 'utf8'
    if (enc === 'utf8')
      return options?.strictUtf8 ? fromUtf8BytesStrict(bytes) : fromUtf8Bytes(bytes)
    if (enc === 'base64') return Buffer.from(bytes).toString('base64')
    if (enc === 'base64url') return base64UrlEncode(bytes)
    if (enc === 'hex') return Buffer.from(bytes).toString('hex')
    return fromUtf8Bytes(bytes)
  }

  async encryptToString(
    input: string | Uint8Array,
    options?: { aad?: string | Uint8Array; canonical?: boolean },
  ): Promise<string> {
    /**
     * @summary Encrypt input and return a canonical JSON string if requested.
     * @param input Plaintext as `string | Uint8Array`.
     * @param options Optional AAD; `canonical` for stable field ordering.
     * @returns JSON string of the envelope.
     */
    const env = await this.encrypt(input, { aad: options?.aad })
    if (options?.canonical) {
      const ordered = {
        v: env.v,
        alg: env.alg,
        kid: env.kid,
        iv: env.iv,
        tag: env.tag,
        ciphertext: env.ciphertext,
        ...(env.aad ? { aad: env.aad } : {}),
      }
      return JSON.stringify(ordered)
    }
    return JSON.stringify(env)
  }

  async decryptFromString(
    envelopeJson: string,
    options?: { aad?: string | Uint8Array },
  ): Promise<Uint8Array> {
    /**
     * @summary Parse an envelope JSON string then decrypt it.
     * @param envelopeJson JSON string representing the envelope.
     * @param options Optional AAD to assert equality.
     * @returns Decrypted plaintext bytes.
     */
    const env = JSON.parse(envelopeJson) as EnvelopeV1
    return this.decrypt(env, { aad: options?.aad })
  }
}
