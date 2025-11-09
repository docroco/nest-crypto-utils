/** JOSE JWS algorithm identifiers supported by this library. */
export type JwsAlg = 'EdDSA' | 'PS256' | 'ES256'
/** JOSE JWE key management algorithm supported. */
export type JweAlg = 'RSA-OAEP-256' | 'ECDH-ES' | 'ECDH-ES+A256KW'
/** JOSE JWE content encryption algorithm supported. */
export type JweEnc = 'A256GCM'

export interface JwsSignOptions {
  kid?: string
  alg?: JwsAlg
  detached?: boolean
  detachedMode?: 'compact-detached' | 'rfc7797'
  protectedHeader?: Record<string, unknown>
  canonical?: boolean
}

export interface JwsVerifyOptions {
  expectedAlg?: JwsAlg
  detachedPayload?: Uint8Array | string
}

export interface JweEncryptOptions {
  kid?: string
  alg?: JweAlg
  enc?: JweEnc
  zip?: 'DEF'
}

export interface JweDecryptOptions {
  expectedAlg?: JweAlg
  expectedEnc?: JweEnc
}

export interface JwtSignOptions {
  kid?: string
  alg?: JwsAlg
  /** Token lifetime (e.g., `30s`, `5m`, `1h`, `1d`, `500ms`, or numeric seconds). */
  expiresIn?: string | number
  issuer?: string
  audience?: string | string[]
  subject?: string
  header?: Record<string, unknown>
  typ?: string
}

export interface JwtVerifyOptions {
  issuer?: string | string[]
  audience?: string | string[]
  subject?: string
  maxSkew?: number
  requireExp?: boolean
  requiredClaims?: string[]
  jwks?: { keys: unknown[] }
  jwksUrls?: string[]
  issuerJwks?: Array<{ issuer: string; jwksUrl: string }>
  algs?: JwsAlg[]
  cacheTtlSeconds?: number
  timeoutMs?: number
  /** If true, require remote JWKS verification and don't fall back to local keystore */
  requireRemoteJwks?: boolean
}
