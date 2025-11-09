export interface EnvelopeStreamMetaV1 {
  v: '1'
  alg: 'AES-256-GCM'
  kid: string
  iv: string // Base64url
  aad?: string // Base64url
}

export interface HmacStreamResultV1 {
  v: '1'
  alg: 'HMAC-SHA256'
  kid: string
  mac: string // Base64url
}
