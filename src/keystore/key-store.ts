import type { Alg, SymmetricAlg, SignAlg, HmacAlg } from '../types/alg'
import type { KeyObject } from 'node:crypto'

/**
 * @summary Abstract keystore for looking up cryptographic keys by algorithm and kid.
 * @remarks
 * Implementations should throw {@link CryptoError} with codes like `KEY_NOT_FOUND` or
 * `UNSUPPORTED_ALG` as appropriate.
 */
export interface KeyStore {
  /**
   * @summary Return the active kid for a given algorithm family.
   */
  getActiveKidFor: (alg: Alg) => string
  /**
   * @summary Return allowed kid list for the provided algorithm.
   */
  getAllowedKidsFor: (alg: Alg) => string[]

  /**
   * @summary Retrieve a symmetric key object for AES-256-GCM by kid.
   */
  getSymmetricKey: (alg: SymmetricAlg, kid: string) => KeyObject

  /**
   * @summary Retrieve an HMAC key object by kid.
   */
  getHmacKey: (alg: HmacAlg, kid: string) => KeyObject

  /**
   * @summary Retrieve a private key (signing) by algorithm and kid.
   */
  getPrivateKey: (alg: SignAlg, kid: string) => KeyObject
  /**
   * @summary Retrieve a public key (verification) by algorithm and kid.
   */
  getPublicKey: (alg: SignAlg, kid: string) => KeyObject
}

export interface EnvKeyStoreOptions {
  env?: NodeJS.ProcessEnv
  requireSymmetric?: boolean
  requireHmac?: boolean
  requireSigning?: boolean
}
