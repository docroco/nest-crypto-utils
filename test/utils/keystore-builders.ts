import { Buffer } from 'node:buffer'
import { generateKeyPairSync, randomBytes } from 'node:crypto'

import { InMemoryKeyStore } from '../../src/keystore/in-memory-key-store'
import { base64UrlEncode } from '../../src/utils/encoding'

/**
 * Fluent builder for creating test keystores with various key configurations.
 * @example
 * ```ts
 * const keystore = new TestKeystoreBuilder()
 *   .withActiveKid('K1')
 *   .withAesKey('K1')
 *   .withHmacKey('K1')
 *   .withEd25519Keys('K1')
 *   .build()
 * ```
 */
export class TestKeystoreBuilder {
  private activeKid = 'K1'
  private aesKeys = new Map<string, Uint8Array>()
  private hmacKeys = new Map<string, Uint8Array>()
  private ed25519Keys = new Map<string, { privPem: string; pubPem: string }>()
  private rsaPssKeys = new Map<string, { privPem: string; pubPem: string }>()
  private p256Keys = new Map<string, { privPem: string; pubPem: string }>()

  /**
   * Set the active key ID.
   */
  withActiveKid(kid: string): this {
    this.activeKid = kid
    return this
  }

  /**
   * Add an AES-256-GCM key. If no key provided, generates a random one.
   */
  withAesKey(kid: string, key?: Uint8Array): this {
    this.aesKeys.set(kid, key ?? new Uint8Array(randomBytes(32)))
    return this
  }

  /**
   * Add an HMAC-SHA256 key. If no key provided, generates a random one.
   */
  withHmacKey(kid: string, key?: Uint8Array): this {
    this.hmacKeys.set(kid, key ?? new Uint8Array(randomBytes(32)))
    return this
  }

  /**
   * Add an Ed25519 key pair. If no PEMs provided, generates a new pair.
   */
  withEd25519Keys(kid: string, privPem?: string, pubPem?: string): this {
    if (privPem && pubPem) {
      this.ed25519Keys.set(kid, { privPem, pubPem })
    } else {
      const { privateKey, publicKey } = generateKeyPairSync('ed25519')
      this.ed25519Keys.set(kid, {
        privPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
        pubPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      })
    }
    return this
  }

  /**
   * Add an RSA-PSS key pair. If no PEMs provided, generates a new pair.
   */
  withRsaPssKeys(kid: string, privPem?: string, pubPem?: string): this {
    if (privPem && pubPem) {
      this.rsaPssKeys.set(kid, { privPem, pubPem })
    } else {
      const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
      this.rsaPssKeys.set(kid, {
        privPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
        pubPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      })
    }
    return this
  }

  /**
   * Add a P-256 key pair. If no PEMs provided, generates a new pair.
   */
  withP256Keys(kid: string, privPem?: string, pubPem?: string): this {
    if (privPem && pubPem) {
      this.p256Keys.set(kid, { privPem, pubPem })
    } else {
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
      })
      this.p256Keys.set(kid, {
        privPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
        pubPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      })
    }
    return this
  }

  /**
   * Build an InMemoryKeyStore with the configured keys.
   */
  build(): InMemoryKeyStore {
    const keystore = new InMemoryKeyStore({ activeKid: this.activeKid })

    for (const [kid, key] of this.aesKeys.entries()) {
      keystore.setSymmetricKey(kid, key)
    }

    for (const [kid, key] of this.hmacKeys.entries()) {
      keystore.setHmacKey(kid, key)
    }

    for (const [kid, { privPem, pubPem }] of this.ed25519Keys.entries()) {
      keystore.setEd25519Keys(kid, privPem, pubPem)
    }

    for (const [kid, { privPem, pubPem }] of this.rsaPssKeys.entries()) {
      keystore.setRsaPssKeys(kid, privPem, pubPem)
    }

    for (const [kid, { privPem, pubPem }] of this.p256Keys.entries()) {
      keystore.setP256Keys(kid, privPem, pubPem)
    }

    return keystore
  }

  /**
   * Build environment variables suitable for EnvKeyStore.
   */
  buildEnv(): Record<string, string> {
    const env: Record<string, string> = {
      CRYPTO_ACTIVE_KID: this.activeKid,
      CRYPTO_ALLOWED_KIDS_AES: [...this.aesKeys.keys()].join(','),
      CRYPTO_ALLOWED_KIDS_SIGN: [
        ...this.ed25519Keys.keys(),
        ...this.rsaPssKeys.keys(),
        ...this.p256Keys.keys(),
      ].join(','),
    }

    for (const [kid, key] of this.aesKeys.entries()) {
      env[`CRYPTO_AES_KEY_${kid}`] = base64UrlEncode(Buffer.from(key))
    }

    for (const [kid, key] of this.hmacKeys.entries()) {
      env[`CRYPTO_HMAC_KEY_${kid}`] = base64UrlEncode(Buffer.from(key))
    }

    for (const [kid, { privPem, pubPem }] of this.ed25519Keys.entries()) {
      env[`CRYPTO_ED25519_PRIV_PEM_${kid}`] = privPem
      env[`CRYPTO_ED25519_PUB_PEM_${kid}`] = pubPem
    }

    for (const [kid, { privPem, pubPem }] of this.rsaPssKeys.entries()) {
      env[`CRYPTO_RSAPS_PRIV_${kid}`] = privPem
      env[`CRYPTO_RSAPS_PUB_${kid}`] = pubPem
    }

    for (const [kid, { privPem, pubPem }] of this.p256Keys.entries()) {
      env[`CRYPTO_P256_PRIV_PEM_${kid}`] = privPem
      env[`CRYPTO_P256_PUB_PEM_${kid}`] = pubPem
    }

    return env
  }
}

