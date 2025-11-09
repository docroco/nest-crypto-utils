import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { promises as fs } from 'node:fs'
import { tmpdir } from 'node:os'
// eslint-disable-next-line unicorn/import-style  -- convenience
import { join } from 'node:path'

import { base64UrlEncode } from '../../../../src/utils/encoding'

/**
 * Setup a temporary key directory for FileKeyStore testing.
 * @param prefix Directory name prefix
 * @returns Path to the created directory
 */
export async function setupTestKeyDirectory(prefix = 'test-keys-'): Promise<string> {
  const rand = Math.random().toString(36).slice(2, 8)
  const dir = join(tmpdir(), `${prefix}${rand}`)

  await fs.mkdir(dir, { recursive: true })

  // Create required metadata files
  await fs.writeFile(join(dir, 'active_kid'), 'K1')
  await fs.writeFile(join(dir, 'allowed_kids_aes'), 'K1')
  await fs.writeFile(join(dir, 'allowed_kids_sign'), 'K1')

  // Create key directories
  await fs.mkdir(join(dir, 'aes'), { recursive: true })
  await fs.mkdir(join(dir, 'hmac'), { recursive: true })
  await fs.mkdir(join(dir, 'ed25519'), { recursive: true })
  await fs.mkdir(join(dir, 'rsaps'), { recursive: true })
  await fs.mkdir(join(dir, 'p256'), { recursive: true })

  // Generate and write test keys
  await fs.writeFile(join(dir, 'aes', 'K1.b64u'), base64UrlEncode(randomBytes(32)))
  await fs.writeFile(join(dir, 'hmac', 'K1.b64u'), base64UrlEncode(randomBytes(32)))

  const { privateKey: edPriv, publicKey: edPub } = generateKeyPairSync('ed25519')
  await fs.writeFile(
    join(dir, 'ed25519', 'priv-K1.pem'),
    edPriv.export({ format: 'pem', type: 'pkcs8' }),
  )
  await fs.writeFile(
    join(dir, 'ed25519', 'pub-K1.pem'),
    edPub.export({ format: 'pem', type: 'spki' }),
  )

  const { privateKey: rsaPriv, publicKey: rsaPub } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  })
  await fs.writeFile(
    join(dir, 'rsaps', 'priv-K1.pem'),
    rsaPriv.export({ format: 'pem', type: 'pkcs8' }),
  )
  await fs.writeFile(
    join(dir, 'rsaps', 'pub-K1.pem'),
    rsaPub.export({ format: 'pem', type: 'spki' }),
  )

  const { privateKey: p256Priv, publicKey: p256Pub } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  })
  await fs.writeFile(
    join(dir, 'p256', 'priv-K1.pem'),
    p256Priv.export({ format: 'pem', type: 'pkcs8' }),
  )
  await fs.writeFile(
    join(dir, 'p256', 'pub-K1.pem'),
    p256Pub.export({ format: 'pem', type: 'spki' }),
  )

  return dir
}

/**
 * Clean up a temporary key directory.
 * @param path Path to the directory to remove
 */
export async function cleanupTestKeyDirectory(path: string): Promise<void> {
  try {
    await fs.rm(path, { recursive: true, force: true })
  } catch (error) {
    // Ignore errors during cleanup
    console.warn(`Failed to cleanup test directory ${path}:`, error)
  }
}
