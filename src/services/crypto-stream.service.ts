/* eslint-disable class-methods-use-this -- this is a service class */
import { Buffer } from 'node:buffer'
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto'
import { Transform } from 'node:stream'

import { Inject, Injectable } from '@nestjs/common'

import { KEY_STORE } from '../module/crypto.module'
import { base64UrlEncode, base64UrlDecode } from '../utils/encoding'

import type { KeyStore } from '../keystore/key-store'
import type { HmacAlg } from '../types/alg'
import type { EnvelopeStreamMetaV1, HmacStreamResultV1 } from '../types/streaming'

const AES = 'AES-256-GCM' as const

/**
 * @summary Streaming APIs for AES-256-GCM encryption/decryption and HMAC-SHA256.
 * @remarks
 * Useful for large payloads; returns Node.js Transform-compatible primitives and
 * metadata needed to finalize or resume operations.
 *
 * ## Security: AES-GCM Nonce Management
 *
 * This service uses **random 96-bit IVs (nonces)** for each encryption stream.
 * The same nonce collision risks apply as in {@link CryptoService}.
 *
 * **Key points:**
 * - Random nonces have collision probability at ~2^48 operations per key
 * - Nonce reuse with AES-GCM completely breaks confidentiality
 * - Rotate keys before 2^32 encryptions (conservative limit)
 *
 * See {@link CryptoService} documentation for detailed security considerations.
 */
@Injectable()
export class CryptoStreamService {
  constructor(@Inject(KEY_STORE) private readonly keyStore: KeyStore) {}

  /**
   * @summary Create an AES-256-GCM encrypt stream.
   * @param options Optional parameters.
   * @param options.aad Additional authenticated data to bind to the ciphertext.
   * @param options.kid Key id to use; defaults to active kid for AES.
   * @returns Envelope metadata and a CipherGCM stream.
   * @throws {@link CryptoError} with code `KEY_NOT_FOUND` via keystore lookup.
   * @example
   * ```ts
   * const { meta, cipher } = svc.createEncryptStream({ aad: 'ctx' })
   * const ct = Buffer.concat([cipher.update(pt), cipher.final()])
   * const { tag } = svc.finalizeEncryptStream(meta, cipher)
   * ```
   */
  createEncryptStream(options?: { aad?: string | Uint8Array; kid?: string }): {
    meta: EnvelopeStreamMetaV1
    cipher: import('node:crypto').CipherGCM
  } {
    const kid = options?.kid ?? this.keyStore.getActiveKidFor(AES)
    const key = this.keyStore.getSymmetricKey(AES, kid)
    // Generate random 96-bit IV (nonce) for GCM mode
    // Note: Random nonces have collision risk at ~2^48 operations per key
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    if (options?.aad)
      cipher.setAAD(
        typeof options.aad === 'string'
          ? new TextEncoder().encode(options.aad)
          : options.aad,
      )
    const meta: EnvelopeStreamMetaV1 = {
      v: '1',
      alg: AES,
      kid,
      iv: base64UrlEncode(iv),
      aad: options?.aad
        ? base64UrlEncode(
            typeof options.aad === 'string'
              ? new TextEncoder().encode(options.aad)
              : options.aad,
          )
        : undefined,
    }
    return { meta, cipher }
  }

  /**
   * @summary Finalize AES-256-GCM encryption and extract the auth tag.
   * @param _meta Envelope metadata from {@link createEncryptStream}.
   * @param cipher Cipher instance used during encryption.
   * @returns Base64url-encoded tag string.
   */
  finalizeEncryptStream(
    _meta: EnvelopeStreamMetaV1,
    cipher: import('node:crypto').CipherGCM,
  ): { tag: string } {
    const tag = cipher.getAuthTag()
    return { tag: base64UrlEncode(tag) }
  }

  /**
   * @summary Create an AES-256-GCM decrypt stream.
   * @param meta Envelope metadata plus tag.
   * @returns A DecipherGCM stream configured with IV, tag, and optional AAD.
   * @throws {@link CryptoError} with code `KEY_NOT_FOUND` via keystore lookup.
   */
  createDecryptStream(
    meta: EnvelopeStreamMetaV1 & { tag: string },
  ): import('node:crypto').DecipherGCM {
    const key = this.keyStore.getSymmetricKey(AES, meta.kid)
    const iv = base64UrlDecode(meta.iv)
    const tag = base64UrlDecode(meta.tag)
    const aad = meta.aad ? base64UrlDecode(meta.aad) : undefined
    const decipher = createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(Buffer.from(tag))
    if (aad) decipher.setAAD(aad)
    return decipher
  }

  /**
   * @summary Compute HMAC-SHA256 over a stream.
   * @param options Optional parameters.
   * @param options.kid Key id to use; defaults to active HMAC kid.
   * @returns Transform that passes data through and a finalize function returning the MAC.
   * @throws {@link CryptoError} with code `KEY_NOT_FOUND` via keystore lookup.
   */
  hmacStream(options?: { kid?: string }): {
    transform: Transform
    finalize: () => HmacStreamResultV1
  } {
    const HMAC_ALG: HmacAlg = 'HMAC-SHA256'
    const kid = options?.kid ?? this.keyStore.getActiveKidFor(HMAC_ALG)
    const key = this.keyStore.getHmacKey(HMAC_ALG, kid)
    const h = createHmac('sha256', key)
    const transform = new Transform({
      transform(chunk, _enc, cb) {
        h.update(chunk)
        cb(null, chunk)
      },
    })
    const finalize = (): HmacStreamResultV1 => ({
      v: '1',
      alg: 'HMAC-SHA256',
      kid,
      mac: base64UrlEncode(h.digest()),
    })
    return { transform, finalize }
  }
}
