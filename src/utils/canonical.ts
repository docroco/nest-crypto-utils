import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'

/**
 * @summary Serialize a value to canonical JSON (stable key ordering).
 * @param value Any JSON-serializable value.
 * @returns Canonical JSON string with lexicographically ordered object keys.
 * @throws {@link CryptoError} with code `INPUT_VALIDATION_ERROR` when circular references detected.
 */
export function canonicalStringify(value: unknown): string {
  const seen = new WeakSet<object>()
  return JSON.stringify(order(value, seen))
}

/**
 * @summary (Private) Recursively sort object keys with circular reference detection.
 */
function order(x: unknown, seen: WeakSet<object>): unknown {
  if (Array.isArray(x)) {
    if (seen.has(x)) {
      throw new CryptoError(
        CryptoErrorCode.INPUT_VALIDATION_ERROR,
        'Circular reference detected in canonicalStringify',
      )
    }
    seen.add(x)
    return x.map(item => order(item, seen))
  }
  if (x && typeof x === 'object') {
    if (seen.has(x)) {
      throw new CryptoError(
        CryptoErrorCode.INPUT_VALIDATION_ERROR,
        'Circular reference detected in canonicalStringify',
      )
    }
    seen.add(x)
    const src = x as Record<string, unknown>
    const sortedKeys = Object.keys(src).sort()
    const obj: Record<string, unknown> = {}
    for (const k of sortedKeys) {
      obj[k] = order(src[k], seen)
    }
    return obj
  }
  return x
}
