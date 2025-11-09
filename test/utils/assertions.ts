import type { CryptoErrorCode } from '../../src/errors/crypto.error'
import type { EnvelopeV1, HmacV1, SignatureV1 } from '../../src/types/envelope'

/**
 * Assert that a promise rejects with a CryptoError of the specified code.
 * @param promise The promise to test
 * @param code Expected CryptoErrorCode
 * @param messageFragment Optional fragment that should appear in the error message
 */
export async function expectCryptoError(
  promise: Promise<unknown>,
  code: CryptoErrorCode,
  messageFragment?: string,
): Promise<void> {
  await expect(promise).rejects.toMatchObject({
    name: 'CryptoError',
    code,
  })

  if (messageFragment) {
    await expect(promise).rejects.toThrow(messageFragment)
  }
}

/**
 * Assert that a value is a valid EnvelopeV1.
 * @param envelope Value to validate
 * @throws If envelope is invalid
 */
export function expectValidEnvelope(envelope: unknown): asserts envelope is EnvelopeV1 {
  expect(envelope).toBeDefined()
  expect(typeof envelope).toBe('object')
  expect(envelope).not.toBeNull()

  const env = envelope as Record<string, unknown>
  expect(env.v).toBe('1')
  expect(env.alg).toBe('AES-256-GCM')
  expect(typeof env.kid).toBe('string')
  expect(typeof env.iv).toBe('string')
  expect(typeof env.tag).toBe('string')
  expect(typeof env.ciphertext).toBe('string')

  // Base64url validation (no padding, no +/)
  expect(env.iv).toMatch(/^[\w-]*$/)
  expect(env.tag).toMatch(/^[\w-]*$/)
  expect(env.ciphertext).toMatch(/^[\w-]*$/)

  if (env.aad !== undefined) {
    expect(typeof env.aad).toBe('string')
    expect(env.aad).toMatch(/^[\w-]*$/)
  }
}

/**
 * Assert that a value is a valid SignatureV1.
 * @param signature Value to validate
 * @throws If signature is invalid
 */
export function expectValidSignature(
  signature: unknown,
): asserts signature is SignatureV1 {
  expect(signature).toBeDefined()
  expect(typeof signature).toBe('object')
  expect(signature).not.toBeNull()

  const sig = signature as Record<string, unknown>
  expect(sig.v).toBe('1')
  expect(['Ed25519', 'RSA-PSS-SHA256', 'P-256']).toContain(sig.alg)
  expect(typeof sig.kid).toBe('string')
  expect(typeof sig.sig).toBe('string')
  expect(sig.sig).toMatch(/^[\w-]*$/)
}

/**
 * Assert that a value is a valid HmacV1.
 * @param mac Value to validate
 * @throws If HMAC is invalid
 */
export function expectValidHmac(mac: unknown): asserts mac is HmacV1 {
  expect(mac).toBeDefined()
  expect(typeof mac).toBe('object')
  expect(mac).not.toBeNull()

  const hmac = mac as Record<string, unknown>
  expect(hmac.v).toBe('1')
  expect(hmac.alg).toBe('HMAC-SHA256')
  expect(typeof hmac.kid).toBe('string')
  expect(typeof hmac.mac).toBe('string')
  expect(hmac.mac).toMatch(/^[\w-]*$/)
}
