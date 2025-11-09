import { Buffer } from 'node:buffer'
import { generateKeyPairSync } from 'node:crypto'

import { base64UrlEncode } from '../../src/utils/encoding'

import type { KeyObject } from 'node:crypto'

/**
 * Common test key IDs used across test suites.
 */
export const TEST_KEY_IDS = {
  DEFAULT: 'K1',
  V1: 'key-v1',
  V2: 'key-v2',
  ALPHA: 'team-alpha',
  BETA: 'team-beta',
} as const

/**
 * Pre-generated AES-256 keys for testing (base64url encoded).
 */
export const TEST_AES_KEYS = new Map<string, string>([
  [TEST_KEY_IDS.DEFAULT, base64UrlEncode(Buffer.alloc(32, 1))],
  [TEST_KEY_IDS.V1, base64UrlEncode(Buffer.alloc(32, 2))],
  [TEST_KEY_IDS.V2, base64UrlEncode(Buffer.alloc(32, 3))],
  [TEST_KEY_IDS.ALPHA, base64UrlEncode(Buffer.alloc(32, 4))],
  [TEST_KEY_IDS.BETA, base64UrlEncode(Buffer.alloc(32, 5))],
])

/**
 * Pre-generated HMAC-SHA256 keys for testing (base64url encoded).
 */
export const TEST_HMAC_KEYS = new Map<string, string>([
  [TEST_KEY_IDS.DEFAULT, base64UrlEncode(Buffer.alloc(32, 6))],
  [TEST_KEY_IDS.V1, base64UrlEncode(Buffer.alloc(32, 7))],
  [TEST_KEY_IDS.V2, base64UrlEncode(Buffer.alloc(32, 8))],
  [TEST_KEY_IDS.ALPHA, base64UrlEncode(Buffer.alloc(32, 9))],
  [TEST_KEY_IDS.BETA, base64UrlEncode(Buffer.alloc(32, 10))],
])

/**
 * Generate Ed25519 key pair for testing.
 */
function generateEd25519Keys(): {
  privateKey: KeyObject
  publicKey: KeyObject
  privPem: string
  pubPem: string
} {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  return {
    privateKey,
    publicKey,
    privPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    pubPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  }
}

/**
 * Generate RSA-PSS key pair for testing.
 */
function generateRsaPssKeys(): {
  privateKey: KeyObject
  publicKey: KeyObject
  privPem: string
  pubPem: string
} {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  return {
    privateKey,
    publicKey,
    privPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    pubPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  }
}

/**
 * Generate P-256 key pair for testing.
 */
function generateP256Keys(): {
  privateKey: KeyObject
  publicKey: KeyObject
  privPem: string
  pubPem: string
} {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  })
  return {
    privateKey,
    publicKey,
    privPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    pubPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  }
}

/**
 * Pre-generated Ed25519 key pairs for testing.
 * Note: These are generated at runtime to avoid storing private keys in source.
 */
export const TEST_ED25519_KEYS = new Map<string, ReturnType<typeof generateEd25519Keys>>([
  [TEST_KEY_IDS.DEFAULT, generateEd25519Keys()],
  [TEST_KEY_IDS.V1, generateEd25519Keys()],
  [TEST_KEY_IDS.V2, generateEd25519Keys()],
])

/**
 * Pre-generated RSA-PSS key pairs for testing.
 */
export const TEST_RSA_KEYS = new Map<string, ReturnType<typeof generateRsaPssKeys>>([
  [TEST_KEY_IDS.DEFAULT, generateRsaPssKeys()],
])

/**
 * Pre-generated P-256 key pairs for testing.
 */
export const TEST_P256_KEYS = new Map<string, ReturnType<typeof generateP256Keys>>([
  [TEST_KEY_IDS.DEFAULT, generateP256Keys()],
])

/**
 * Generate environment variables for testing with specified keys.
 * @param kid The key ID to use as active
 * @param keyTypes Array of key types to include: 'aes', 'hmac', 'ed25519', 'rsa', 'p256'
 * @returns Object containing environment variable key-value pairs
 */
export function getTestEnv(
  kid: string = TEST_KEY_IDS.DEFAULT,
  keyTypes: Array<'aes' | 'hmac' | 'ed25519' | 'rsa' | 'p256'> = ['aes', 'hmac'],
): Record<string, string> {
  const env: Record<string, string> = {
    CRYPTO_ACTIVE_KID: kid,
    CRYPTO_ALLOWED_KIDS_AES: '',
    CRYPTO_ALLOWED_KIDS_SIGN: '',
  }

  if (keyTypes.includes('aes') && TEST_AES_KEYS.has(kid)) {
    env[`CRYPTO_AES_KEY_${kid}`] = TEST_AES_KEYS.get(kid) ?? ''
  }

  if (keyTypes.includes('hmac') && TEST_HMAC_KEYS.has(kid)) {
    env[`CRYPTO_HMAC_KEY_${kid}`] = TEST_HMAC_KEYS.get(kid) ?? ''
  }

  if (keyTypes.includes('ed25519')) {
    const keys = TEST_ED25519_KEYS.get(kid) ?? generateEd25519Keys()
    env[`CRYPTO_ED25519_PRIV_PEM_${kid}`] = keys.privPem
    env[`CRYPTO_ED25519_PUB_PEM_${kid}`] = keys.pubPem
  }

  if (keyTypes.includes('rsa')) {
    const keys = TEST_RSA_KEYS.get(kid) ?? generateRsaPssKeys()
    env[`CRYPTO_RSAPS_PRIV_${kid}`] = keys.privPem
    env[`CRYPTO_RSAPS_PUB_${kid}`] = keys.pubPem
  }

  if (keyTypes.includes('p256')) {
    const keys = TEST_P256_KEYS.get(kid) ?? generateP256Keys()
    env[`CRYPTO_P256_PRIV_PEM_${kid}`] = keys.privPem
    env[`CRYPTO_P256_PUB_PEM_${kid}`] = keys.pubPem
  }

  return env
}
