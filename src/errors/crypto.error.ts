/**
 * @summary Error codes for cryptographic operations and configuration.
 */
export enum CryptoErrorCode {
  KEY_NOT_FOUND = 'KEY_NOT_FOUND',
  INVALID_KEY_MATERIAL = 'INVALID_KEY_MATERIAL',
  UNSUPPORTED_ALG = 'UNSUPPORTED_ALG',
  INVALID_ENVELOPE = 'INVALID_ENVELOPE',
  DECRYPT_AUTH_FAILED = 'DECRYPT_AUTH_FAILED',
  SIGN_VERIFY_FAILED = 'SIGN_VERIFY_FAILED',
  ENCODING_ERROR = 'ENCODING_ERROR',
  CONFIG_ERROR = 'CONFIG_ERROR',
  INPUT_VALIDATION_ERROR = 'INPUT_VALIDATION_ERROR',
  SIZE_LIMIT_EXCEEDED = 'SIZE_LIMIT_EXCEEDED',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
}

/**
 * @summary Custom error carrying a {@link CryptoErrorCode} and optional details.
 */
export class CryptoError extends Error {
  readonly code: CryptoErrorCode
  readonly details?: Record<string, unknown>

  /**
   * @summary Construct a CryptoError.
   * @param code Machine-readable error code.
   * @param message Optional human-readable message.
   * @param details Optional structured details for diagnostics.
   */
  constructor(
    code: CryptoErrorCode,
    message?: string,
    details?: Record<string, unknown>,
  ) {
    super(message ?? code)
    this.name = 'CryptoError'
    this.code = code
    this.details = details
  }
}
