import type { Buffer } from 'node:buffer'

export type BinaryLike = string | Uint8Array | Buffer

/**
 * @summary Convert a string/Buffer/Uint8Array to Uint8Array.
 * @param input The value to convert.
 * @returns A Uint8Array view of the input.
 */
export function toBytes(input: BinaryLike): Uint8Array {
  if (typeof input === 'string') {
    return new TextEncoder().encode(input)
  }
  if (input instanceof Uint8Array) {
    return input
  }
  return new Uint8Array(input)
}

/**
 * @summary Concatenate multiple byte arrays.
 * @param chunks One or more Uint8Array chunks.
 * @returns A new Uint8Array containing all chunks in order.
 */
export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

/**
 * @summary Overwrite the provided byte array with zeros for secure memory clearing.
 * @param bytes The array to zeroize.
 * @remarks
 * Use this function to clear sensitive data (passwords, keys, tokens) from memory
 * after use. While JavaScript's garbage collector will eventually reclaim memory,
 * this provides defense-in-depth by immediately overwriting sensitive values.
 *
 * **Important Limitations:**
 * - JavaScript strings are immutable and cannot be zeroized
 * - The garbage collector may leave copies in memory
 * - This is not a complete solution for memory security in JavaScript
 * - For maximum security, avoid storing sensitive data in JavaScript when possible
 *
 * **Best Practices:**
 * - Use `Uint8Array` for sensitive data instead of strings
 * - Call `zeroize()` immediately after use
 * - Avoid logging or serializing sensitive data
 * - Consider using short-lived processes for highly sensitive operations
 *
 * @example
 * ```ts
 * const password = new TextEncoder().encode('secret')
 * // ... use password ...
 * zeroize(password) // Clear from memory
 * ```
 */
export function zeroize(bytes: Uint8Array): void {
  bytes.fill(0)
}
