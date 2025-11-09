/** Algorithm identifiers for symmetric encryption. */
export type SymmetricAlg = 'AES-256-GCM'
/** Algorithm identifiers for HMAC. */
export type HmacAlg = 'HMAC-SHA256'
/** Supported signing algorithms. */
export type SignAlg = 'Ed25519' | 'RSA-PSS-SHA256' | 'P-256'

/** Union of all supported algorithm identifiers. */
export type Alg = SymmetricAlg | HmacAlg | SignAlg
