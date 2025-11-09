import { Buffer } from 'node:buffer'
import { createPrivateKey, createPublicKey, createSecretKey } from 'node:crypto'

import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'

import type { KeyStore } from './key-store'
import type { Alg, HmacAlg, SignAlg, SymmetricAlg } from '../types/alg'
import type { KeyObject } from 'node:crypto'

/**
 * @summary Options for constructing an in-memory keystore.
 */
export interface InMemoryKeyStoreOptions {
  activeKid: string
  allowedKidsAes?: string[]
  allowedKidsSign?: string[]
}
/**
 * @summary Ephemeral keystore ideal for unit tests and local fixtures.
 * @remarks
 * Maintains key material in process memory and exposes helper setters for symmetric,
 * HMAC, and signing keys. Mirrors the {@link KeyStore} contract used by production
 * keystores without requiring external resources.
 */
export class InMemoryKeyStore implements KeyStore {
  private activeKid: string

  private allowedKidsAes: Set<string>

  private allowedKidsSign: Set<string>

  private symmetricKeys = new Map<string, KeyObject>()

  private hmacKeys = new Map<string, KeyObject>()

  private privKeys = new Map<string, KeyObject>()

  private pubKeys = new Map<string, KeyObject>()

  /**
   * @summary Create an in-memory keystore and seed allowed key identifiers.
   * @param options Active key id plus optional pre-approved lists for AES/HMAC and signing.
   */
  constructor(options: InMemoryKeyStoreOptions) {
    this.activeKid = options.activeKid
    this.allowedKidsAes = new Set([...(options.allowedKidsAes ?? []), this.activeKid])
    this.allowedKidsSign = new Set([...(options.allowedKidsSign ?? []), this.activeKid])
  }

  /**
   * @summary Register an AES-256-GCM key.
   * @throws {@link CryptoError} with code `INVALID_KEY_MATERIAL` when key length is not 32 bytes.
   */
  setSymmetricKey(kid: string, keyBytes: Uint8Array): this {
    if (keyBytes.length !== 32)
      throw new CryptoError(
        CryptoErrorCode.INVALID_KEY_MATERIAL,
        'AES key must be 32 bytes',
        { kid },
      )
    this.symmetricKeys.set(kid, createSecretKey(Buffer.from(keyBytes)))
    this.allowedKidsAes.add(kid)
    return this
  }

  /**
   * @summary Register an HMAC-SHA256 key.
   * @remarks
   * This library enforces a 32-byte (256-bit) minimum for HMAC keys to ensure
   * adequate security margin. While HMAC technically works with shorter keys,
   * NIST SP 800-107 recommends key lengths equal to or greater than the hash
   * output size (32 bytes for SHA-256) to achieve full security strength.
   * Reference: NIST SP 800-107 Rev. 1, Section 5.3.4
   * @throws {@link CryptoError} with code `INVALID_KEY_MATERIAL` when key length is less than 32 bytes.
   */
  setHmacKey(kid: string, keyBytes: Uint8Array): this {
    if (keyBytes.length < 32)
      throw new CryptoError(
        CryptoErrorCode.INVALID_KEY_MATERIAL,
        'HMAC key must be >=32 bytes',
        { kid },
      )
    this.hmacKeys.set(kid, createSecretKey(Buffer.from(keyBytes)))
    this.allowedKidsAes.add(kid)
    return this
  }

  /**
   * @summary Register an Ed25519 key pair (PEM strings).
   */
  setEd25519Keys(kid: string, privPem: string, pubPem: string): this {
    this.privKeys.set(`Ed25519:${kid}`, createPrivateKey(privPem))
    this.pubKeys.set(`Ed25519:${kid}`, createPublicKey(pubPem))
    this.allowedKidsSign.add(kid)
    return this
  }

  /**
   * @summary Register an RSA-PSS-SHA256 key pair (PEM strings).
   */
  setRsaPssKeys(kid: string, privPem: string, pubPem: string): this {
    this.privKeys.set(`RSA-PSS-SHA256:${kid}`, createPrivateKey(privPem))
    this.pubKeys.set(`RSA-PSS-SHA256:${kid}`, createPublicKey(pubPem))
    this.allowedKidsSign.add(kid)
    return this
  }

  /**
   * @summary Register a P-256 key pair usable for ES256 or ECDH-ES operations.
   */
  setP256Keys(kid: string, privPem: string, pubPem: string): this {
    this.privKeys.set(`P-256:${kid}`, createPrivateKey(privPem))
    this.pubKeys.set(`P-256:${kid}`, createPublicKey(pubPem))
    this.allowedKidsSign.add(kid)
    return this
  }

  /**
   * @summary Override the active key identifier used for default operations.
   */
  setActiveKid(kid: string): void {
    this.activeKid = kid
  }

  /**
   * @summary Return the active key identifier for any algorithm family.
   */
  getActiveKidFor(_alg: Alg): string {
    return this.activeKid
  }

  /**
   * @summary Enumerate allowed key identifiers for the supplied algorithm family.
   */
  getAllowedKidsFor(alg: Alg): string[] {
    if (alg === 'AES-256-GCM' || alg === 'HMAC-SHA256') return [...this.allowedKidsAes]
    return [...this.allowedKidsSign]
  }

  /**
   * @summary Retrieve an AES-256-GCM key.
   * @throws {@link CryptoError} with code `UNSUPPORTED_ALG` or `KEY_NOT_FOUND` when unavailable.
   */
  getSymmetricKey(alg: SymmetricAlg, kid: string): KeyObject {
    if (alg !== 'AES-256-GCM')
      throw new CryptoError(
        CryptoErrorCode.UNSUPPORTED_ALG,
        `Unsupported symmetric alg: ${alg}`,
      )
    const key = this.symmetricKeys.get(kid)
    if (!key)
      throw new CryptoError(CryptoErrorCode.KEY_NOT_FOUND, 'AES key not found', { kid })
    return key
  }

  /**
   * @summary Retrieve an HMAC-SHA256 key.
   * @throws {@link CryptoError} with code `UNSUPPORTED_ALG` or `KEY_NOT_FOUND` when unavailable.
   */
  getHmacKey(alg: HmacAlg, kid: string): KeyObject {
    if (alg !== 'HMAC-SHA256')
      throw new CryptoError(
        CryptoErrorCode.UNSUPPORTED_ALG,
        `Unsupported HMAC alg: ${alg}`,
      )
    const key = this.hmacKeys.get(kid)
    if (!key)
      throw new CryptoError(CryptoErrorCode.KEY_NOT_FOUND, 'HMAC key not found', { kid })
    return key
  }

  /**
   * @summary Retrieve a private signing key by algorithm and key id.
   * @throws {@link CryptoError} with code `KEY_NOT_FOUND` when missing.
   */
  getPrivateKey(alg: SignAlg, kid: string): KeyObject {
    const key = this.privKeys.get(`${alg}:${kid}`)
    if (!key)
      throw new CryptoError(CryptoErrorCode.KEY_NOT_FOUND, 'Private key not found', {
        alg,
        kid,
      })
    return key
  }

  /**
   * @summary Retrieve a public verification key by algorithm and key id.
   * @throws {@link CryptoError} with code `KEY_NOT_FOUND` when missing.
   */
  getPublicKey(alg: SignAlg, kid: string): KeyObject {
    const key = this.pubKeys.get(`${alg}:${kid}`)
    if (!key)
      throw new CryptoError(CryptoErrorCode.KEY_NOT_FOUND, 'Public key not found', {
        alg,
        kid,
      })
    return key
  }
}
