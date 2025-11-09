import type { SymmetricAlg, HmacAlg, SignAlg } from './alg'

/**
 * @summary Envelope for AES-256-GCM ciphertext with associated metadata.
 */
export interface EnvelopeV1 {
  v: '1'
  alg: SymmetricAlg
  kid: string
  iv: string // Base64url
  tag: string // Base64url
  ciphertext: string // Base64url
  aad?: string // Base64url
}

/**
 * @summary Detached signature representation with algorithm and key id.
 */
export interface SignatureV1 {
  v: '1'
  alg: SignAlg
  kid: string
  sig: string // Base64url
}

/**
 * @summary HMAC result representation with algorithm and key id.
 */
export interface HmacV1 {
  v: '1'
  alg: HmacAlg
  kid: string
  mac: string // Base64url
}
