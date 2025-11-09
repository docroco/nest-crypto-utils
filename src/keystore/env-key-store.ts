import { Buffer } from 'node:buffer'
import { createSecretKey, createPrivateKey, createPublicKey } from 'node:crypto'

import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'
import { base64UrlDecode } from '../utils/encoding'

import type { EnvKeyStoreOptions, KeyStore } from './key-store'
import type { Alg, SignAlg, SymmetricAlg } from '../types/alg'
import type { KeyObject } from 'node:crypto'

const AES_ALG: SymmetricAlg = 'AES-256-GCM'
const HMAC_ALG = 'HMAC-SHA256' as const

/**
 * @summary Resolve an environment variable or throw a configuration error when missing.
 * @param env Environment map to read from.
 * @param key Variable name to fetch.
 * @throws {@link CryptoError} when the variable is absent or empty.
 */
function envOrThrow(env: NodeJS.ProcessEnv, key: string): string {
  const v = env[key]
  if (!v) throw new CryptoError(CryptoErrorCode.CONFIG_ERROR, `Missing env ${key}`)
  return v
}
/**
 * @summary Keystore backed by environment variables for symmetric, HMAC, and signing keys.
 * @remarks
 * Reads key material eagerly based on active/allowed key identifiers. Supports PEM or DER
 * encodings for Ed25519 and P-256 keys and base64url material for symmetric/HMAC keys.
 * Optional enforcement flags ensure required key classes are present at construction time.
 */
export class EnvKeyStore implements KeyStore {
  private env: NodeJS.ProcessEnv
  private activeKid: null | string = null
  private allowedKidsAes = new Set<string>()
  private allowedKidsSign = new Set<string>()
  private symmetricKeys = new Map<string, KeyObject>()
  private hmacKeys = new Map<string, KeyObject>()
  private privKeys = new Map<string, KeyObject>()
  private pubKeys = new Map<string, KeyObject>()

  /**
   * @summary Create an environment-backed keystore.
   * @param options Optional overrides supplying a custom environment snapshot and
   * enforcement flags for required key categories.
   * @throws {@link CryptoError} when required environment variables or key material are
   * missing or invalid.
   */
  constructor(options: EnvKeyStoreOptions = {}) {
    this.env = options.env ?? process.env
    this.loadKeys(options)
  }

  private loadKeys(options?: EnvKeyStoreOptions): void {
    const env = this.env
    this.activeKid = envOrThrow(env, 'CRYPTO_ACTIVE_KID')
    if (!this.activeKid.trim()) {
      throw new CryptoError(
        CryptoErrorCode.CONFIG_ERROR,
        'CRYPTO_ACTIVE_KID cannot be empty or whitespace',
      )
    }
    this.allowedKidsAes = new Set([
      ...(env.CRYPTO_ALLOWED_KIDS_AES ?? '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean),
      this.activeKid,
    ])
    this.allowedKidsSign = new Set([
      ...(env.CRYPTO_ALLOWED_KIDS_SIGN ?? '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean),
      this.activeKid,
    ])

    this.symmetricKeys.clear()
    this.hmacKeys.clear()
    this.privKeys.clear()
    this.pubKeys.clear()

    for (const kid of this.allowedKidsAes) {
      const aesVar = `CRYPTO_AES_KEY_${kid}`
      const hmacVar = `CRYPTO_HMAC_KEY_${kid}`
      const aes = this.env[aesVar]
      const hmac = this.env[hmacVar]
      if (aes) {
        const keyBytes = base64UrlDecode(aes)
        if (keyBytes.length !== 32) {
          throw new CryptoError(
            CryptoErrorCode.INVALID_KEY_MATERIAL,
            'AES key must be 32 bytes',
            { kid },
          )
        }
        this.symmetricKeys.set(kid, createSecretKey(Buffer.from(keyBytes)))
      }
      if (hmac) {
        const keyBytes = base64UrlDecode(hmac)

        if (keyBytes.length < 32) {
          throw new CryptoError(
            CryptoErrorCode.INVALID_KEY_MATERIAL,
            'HMAC key must be >=32 bytes',
            { kid },
          )
        }
        this.hmacKeys.set(kid, createSecretKey(Buffer.from(keyBytes)))
      }
    }

    for (const kid of this.allowedKidsSign) {
      const edPriv = this.env[`CRYPTO_ED25519_PRIV_${kid}`]
      const edPrivPem = this.env[`CRYPTO_ED25519_PRIV_PEM_${kid}`]
      const edPub = this.env[`CRYPTO_ED25519_PUB_${kid}`]
      const edPubPem = this.env[`CRYPTO_ED25519_PUB_PEM_${kid}`]

      if (edPriv || edPrivPem) {
        const pem = edPrivPem as string | undefined
        const isDer = !!edPriv
        const key = isDer
          ? Buffer.from(base64UrlDecode(edPriv as string))
          : Buffer.from(pem ?? '', 'utf8')
        try {
          this.privKeys.set(
            `Ed25519:${kid}`,
            isDer
              ? createPrivateKey({ key, format: 'der', type: 'pkcs8' })
              : createPrivateKey(key),
          )
        } catch (error) {
          throw new CryptoError(
            CryptoErrorCode.INVALID_KEY_MATERIAL,
            `Ed25519 private key must be PKCS8 DER (base64url) or PKCS8 PEM: ${error instanceof Error ? error.message : String(error)}`,
            { kid },
          )
        }
      }
      if (edPub || edPubPem) {
        const pem = edPubPem as string | undefined
        const isDer = !!edPub
        const key = isDer
          ? Buffer.from(base64UrlDecode(edPub as string))
          : Buffer.from(pem ?? '', 'utf8')
        try {
          this.pubKeys.set(
            `Ed25519:${kid}`,
            isDer
              ? createPublicKey({ key, format: 'der', type: 'spki' })
              : createPublicKey(key),
          )
        } catch (error) {
          throw new CryptoError(
            CryptoErrorCode.INVALID_KEY_MATERIAL,
            `Ed25519 public key must be SPKI DER (base64url) or SPKI PEM: ${error instanceof Error ? error.message : String(error)}`,
            { kid },
          )
        }
      }

      const rsaPrivPem = this.env[`CRYPTO_RSAPS_PRIV_${kid}`]
      const rsaPubPem = this.env[`CRYPTO_RSAPS_PUB_${kid}`]
      if (rsaPrivPem)
        this.privKeys.set(`RSA-PSS-SHA256:${kid}`, createPrivateKey(rsaPrivPem))
      if (rsaPubPem) this.pubKeys.set(`RSA-PSS-SHA256:${kid}`, createPublicKey(rsaPubPem))

      const p256Priv = this.env[`CRYPTO_P256_PRIV_${kid}`]
      const p256PrivPem = this.env[`CRYPTO_P256_PRIV_PEM_${kid}`]
      const p256Pub = this.env[`CRYPTO_P256_PUB_${kid}`]
      const p256PubPem = this.env[`CRYPTO_P256_PUB_PEM_${kid}`]
      if (p256Priv || p256PrivPem) {
        const pem = p256PrivPem as string | undefined
        const isDer = !!p256Priv
        const key = isDer
          ? Buffer.from(base64UrlDecode(p256Priv as string))
          : Buffer.from(pem ?? '', 'utf8')
        this.privKeys.set(
          `P-256:${kid}`,
          isDer
            ? createPrivateKey({ key, format: 'der', type: 'pkcs8' })
            : createPrivateKey(key),
        )
      }
      if (p256Pub || p256PubPem) {
        const pem = p256PubPem as string | undefined
        const isDer = !!p256Pub
        const key = isDer
          ? Buffer.from(base64UrlDecode(p256Pub as string))
          : Buffer.from(pem ?? '', 'utf8')
        this.pubKeys.set(
          `P-256:${kid}`,
          isDer
            ? createPublicKey({ key, format: 'der', type: 'spki' })
            : createPublicKey(key),
        )
      }
    }

    if (options?.requireSymmetric) {
      const hasAny = [...this.allowedKidsAes].some(kid => this.symmetricKeys.has(kid))
      if (!hasAny)
        throw new CryptoError(
          CryptoErrorCode.CONFIG_ERROR,
          'Symmetric keys required but none loaded',
        )
    }
    if (options?.requireHmac) {
      const hasAny = [...this.allowedKidsAes].some(kid => this.hmacKeys.has(kid))
      if (!hasAny)
        throw new CryptoError(
          CryptoErrorCode.CONFIG_ERROR,
          'HMAC keys required but none loaded',
        )
    }
    if (options?.requireSigning) {
      const hasAny = [...this.allowedKidsSign].some(
        kid =>
          this.pubKeys.has(`Ed25519:${kid}`) ||
          this.privKeys.has(`Ed25519:${kid}`) ||
          this.pubKeys.has(`RSA-PSS-SHA256:${kid}`) ||
          this.privKeys.has(`RSA-PSS-SHA256:${kid}`) ||
          this.pubKeys.has(`P-256:${kid}`) ||
          this.privKeys.has(`P-256:${kid}`),
      )
      if (!hasAny)
        throw new CryptoError(
          CryptoErrorCode.CONFIG_ERROR,
          'Signing keys required but none loaded',
        )
    }
  }

  /**
   * @summary Return the current active key identifier for any algorithm family.
   */
  getActiveKidFor(_alg: Alg): string {
    if (!this.activeKid) {
      throw new CryptoError(CryptoErrorCode.CONFIG_ERROR, 'No active key set')
    }

    return this.activeKid
  }

  /**
   * @summary Reload key material from the existing or provided environment snapshot.
   * @param newEnv Optional environment map to adopt prior to reloading keys.
   * @throws {@link CryptoError} when required variables or key bytes are invalid.
   */
  reload(newEnv?: NodeJS.ProcessEnv): void {
    if (newEnv) {
      this.env = newEnv
    }
    this.loadKeys()
  }

  /**
   * @summary List allowed key identifiers for the requested algorithm family.
   * @param alg Algorithm identifier.
   * @returns Array of key ids permitted for the algorithm.
   */
  getAllowedKidsFor(alg: Alg): string[] {
    if (alg === AES_ALG || alg === HMAC_ALG) return [...this.allowedKidsAes]
    return [...this.allowedKidsSign]
  }

  /**
   * @summary Retrieve an AES-256-GCM key for the supplied key id.
   * @param alg Must be `AES-256-GCM`.
   * @param kid Key identifier.
   * @returns Node.js `KeyObject` for AES usage.
   * @throws {@link CryptoError} with code `UNSUPPORTED_ALG` or `KEY_NOT_FOUND` when the
   * request cannot be satisfied.
   */
  getSymmetricKey(alg: SymmetricAlg, kid: string): KeyObject {
    if (alg !== AES_ALG)
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
   * @summary Retrieve an HMAC-SHA256 key for the supplied key id.
   * @param alg Must be `HMAC-SHA256`.
   * @param kid Key identifier.
   * @throws {@link CryptoError} with code `UNSUPPORTED_ALG` or `KEY_NOT_FOUND` when the key
   * cannot be provided.
   */
  getHmacKey(alg: 'HMAC-SHA256', kid: string): KeyObject {
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
   * @summary Retrieve a private signing key for the given algorithm and key id.
   * @throws {@link CryptoError} with code `KEY_NOT_FOUND` when the keystore lacks the key.
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
   * @summary Retrieve a public verification key for the given algorithm and key id.
   * @throws {@link CryptoError} with code `KEY_NOT_FOUND` when the keystore lacks the key.
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
