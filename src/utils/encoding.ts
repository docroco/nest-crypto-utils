import { Buffer } from 'node:buffer'

import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'

/**
 * @summary Convert a UTF-8 string to bytes.
 * @param input String to encode.
 * @returns UTF-8 byte representation.
 * @example
 * ```ts
 * const bytes = toUtf8Bytes('hello')
 * ```
 */
export function toUtf8Bytes(input: string): Uint8Array {
  return new TextEncoder().encode(input)
}

/**
 * @summary Convert bytes to UTF-8 string (non-strict, replaces invalid sequences).
 * @param bytes Byte array to decode.
 * @returns UTF-8 string with invalid sequences replaced by replacement character.
 * @example
 * ```ts
 * const text = fromUtf8Bytes(bytes)
 * ```
 */
export function fromUtf8Bytes(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes)
}

/**
 * @summary Convert bytes to UTF-8 string (strict mode).
 * @param bytes Byte array to decode.
 * @returns UTF-8 string.
 * @throws Error when bytes contain invalid UTF-8 sequences.
 * @example
 * ```ts
 * const text = fromUtf8BytesStrict(bytes)
 * ```
 */
export function fromUtf8BytesStrict(bytes: Uint8Array): string {
  return new TextDecoder('utf8', { fatal: true }).decode(bytes)
}

/**
 * @summary Encode bytes to base64url string (URL-safe, no padding).
 * @param bytes Byte array to encode.
 * @returns Base64url-encoded string.
 * @example
 * ```ts
 * const encoded = base64UrlEncode(bytes)
 * ```
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  const b64 = Buffer.from(bytes).toString('base64')
  return b64.replaceAll('=', '').replaceAll('+', '-').replaceAll('/', '_')
}

/**
 * @summary Decode base64url string to bytes.
 * @param input Base64url-encoded string (URL-safe, no padding).
 * @returns Decoded byte array.
 * @throws {@link CryptoError} with code `ENCODING_ERROR` when input is malformed.
 * @example
 * ```ts
 * const bytes = base64UrlDecode('AQID')
 * ```
 */
export function base64UrlDecode(input: string): Uint8Array {
  // Validate input contains only base64url characters
  if (!/^[\w-]*$/.test(input)) {
    throw new CryptoError(
      CryptoErrorCode.ENCODING_ERROR,
      'Invalid base64url string: contains illegal characters',
    )
  }

  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4))
  const b64 = input.replaceAll('-', '+').replaceAll('_', '/') + pad

  try {
    return new Uint8Array(Buffer.from(b64, 'base64'))
  } catch (error) {
    throw new CryptoError(
      CryptoErrorCode.ENCODING_ERROR,
      `Failed to decode base64url: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
}
