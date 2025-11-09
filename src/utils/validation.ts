import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'

import type { EnvelopeV1, HmacV1, SignatureV1 } from '../types/envelope'

/**
 * @summary Assert that a string is valid base64url.
 * @param name Descriptive name for error messages.
 * @param value String to validate.
 * @throws {@link CryptoError} with code `ENCODING_ERROR` if invalid.
 */
export function assertBase64Url(name: string, value: string): void {
  if (!/^[\w-]*$/.test(value)) {
    throw new CryptoError(CryptoErrorCode.ENCODING_ERROR, `${name} must be base64url`)
  }
}

/**
 * @summary Assert that a byte array has an exact length.
 * @param name Descriptive name for error messages.
 * @param bytes Byte array to validate.
 * @param expected Expected length in bytes.
 * @throws {@link CryptoError} with code `INPUT_VALIDATION_ERROR` if length doesn't match.
 */
export function assertLength(name: string, bytes: Uint8Array, expected: number): void {
  if (bytes.length !== expected) {
    throw new CryptoError(
      CryptoErrorCode.INPUT_VALIDATION_ERROR,
      `${name} must be ${expected} bytes`,
    )
  }
}

/**
 * @summary Assert that a byte array meets a minimum length.
 * @param name Descriptive name for error messages.
 * @param bytes Byte array to validate.
 * @param min Minimum length in bytes.
 * @throws {@link CryptoError} with code `INPUT_VALIDATION_ERROR` if too short.
 */
export function assertMinLength(name: string, bytes: Uint8Array, min: number): void {
  if (bytes.length < min) {
    throw new CryptoError(
      CryptoErrorCode.INPUT_VALIDATION_ERROR,
      `${name} must be at least ${min} bytes`,
    )
  }
}

/**
 * @summary Assert that a byte array doesn't exceed a maximum size.
 * @param name Descriptive name for error messages.
 * @param bytes Byte array to validate.
 * @param maxSize Maximum size in bytes.
 * @throws {@link CryptoError} with code `SIZE_LIMIT_EXCEEDED` if too large.
 */
export function assertMaxSize(name: string, bytes: Uint8Array, maxSize: number): void {
  if (bytes.length > maxSize) {
    throw new CryptoError(
      CryptoErrorCode.SIZE_LIMIT_EXCEEDED,
      `${name} exceeds maximum size of ${maxSize} bytes (got ${bytes.length} bytes)`,
    )
  }
}

/**
 * @summary Type guard to check if a value is a valid EnvelopeV1.
 * @param value Value to check.
 * @returns True if value is a valid EnvelopeV1, false otherwise.
 * @example
 * ```ts
 * const data = JSON.parse(untrustedInput)
 * if (isEnvelopeV1(data)) {
 *   // TypeScript knows data is EnvelopeV1
 *   const plaintext = await crypto.decrypt(data)
 * }
 * ```
 */
export function isEnvelopeV1(value: unknown): value is EnvelopeV1 {
  if (!value || typeof value !== 'object') return false
  const obj = value as Record<string, unknown>
  return (
    obj.v === '1' &&
    obj.alg === 'AES-256-GCM' &&
    typeof obj.kid === 'string' &&
    typeof obj.iv === 'string' &&
    typeof obj.tag === 'string' &&
    typeof obj.ciphertext === 'string' &&
    (obj.aad === undefined || typeof obj.aad === 'string')
  )
}

/**
 * @summary Type guard to check if a value is a valid SignatureV1.
 * @param value Value to check.
 * @returns True if value is a valid SignatureV1, false otherwise.
 * @example
 * ```ts
 * const data = JSON.parse(untrustedInput)
 * if (isSignatureV1(data)) {
 *   // TypeScript knows data is SignatureV1
 *   const valid = await signing.verify(message, data)
 * }
 * ```
 */
export function isSignatureV1(value: unknown): value is SignatureV1 {
  if (!value || typeof value !== 'object') return false
  const obj = value as Record<string, unknown>
  return (
    obj.v === '1' &&
    (obj.alg === 'Ed25519' || obj.alg === 'RSA-PSS-SHA256' || obj.alg === 'P-256') &&
    typeof obj.kid === 'string' &&
    typeof obj.sig === 'string'
  )
}

/**
 * @summary Type guard to check if a value is a valid HmacV1.
 * @param value Value to check.
 * @returns True if value is a valid HmacV1, false otherwise.
 * @example
 * ```ts
 * const data = JSON.parse(untrustedInput)
 * if (isHmacV1(data)) {
 *   // TypeScript knows data is HmacV1
 *   console.log('HMAC kid:', data.kid)
 * }
 * ```
 */
export function isHmacV1(value: unknown): value is HmacV1 {
  if (!value || typeof value !== 'object') return false
  const obj = value as Record<string, unknown>
  return (
    obj.v === '1' &&
    obj.alg === 'HMAC-SHA256' &&
    typeof obj.kid === 'string' &&
    typeof obj.mac === 'string'
  )
}
