/* eslint-disable unicorn/consistent-function-scoping -- convenience */
/* eslint-disable unicorn/import-style -- convenience */
/* eslint-disable node/prefer-global/buffer -- convenience */

import { generateKeyPairSync } from 'node:crypto'
import { promises as fs } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import { CryptoError } from '../errors/crypto.error'
import { base64UrlEncode } from '../utils/encoding'

import { FileKeyStore } from './file-key-store'

import type { Logger } from '@nestjs/common'

async function mkdtemp(prefix: string): Promise<string> {
  const rand = Math.random().toString(36).slice(2, 8)
  const dir = join(tmpdir(), `${prefix}-${rand}`)
  await fs.mkdir(dir, { recursive: true })
  return dir
}

describe('FileKeyStore', () => {
  async function writePem(dir: string, path: string, contents: string): Promise<void> {
    const full = join(dir, path)
    await fs.mkdir(dirname(full), { recursive: true })
    await fs.writeFile(full, contents)
  }

  it('throws when active_kid missing', async () => {
    const root = await mkdtemp('fks')
    const ks = new FileKeyStore({ directory: root })
    await expect(ks.reload()).rejects.toBeDefined()
  })

  it('loads AES/HMAC and preserves dot kids', async () => {
    const root = await mkdtemp('fks')
    await fs.writeFile(join(root, 'active_kid'), 'team.alpha')
    await fs.writeFile(join(root, 'allowed_kids_aes'), 'team.alpha')
    await fs.writeFile(join(root, 'allowed_kids_sign'), '')
    await fs.mkdir(join(root, 'aes'), { recursive: true })
    await fs.mkdir(join(root, 'hmac'), { recursive: true })
    await fs.writeFile(
      join(root, 'aes', 'team.alpha.b64u'),
      base64UrlEncode(Buffer.alloc(32, 1)),
    )
    await fs.writeFile(
      join(root, 'hmac', 'team.alpha.b64u'),
      base64UrlEncode(Buffer.alloc(32, 2)),
    )
    const ks = new FileKeyStore({ directory: root })
    await ks.reload()
    const k = ks.getSymmetricKey('AES-256-GCM', 'team.alpha')
    expect(k).toBeDefined()
  })

  it('missing kid lookups throw and invalid lengths rejected', async () => {
    const root = await mkdtemp('fks2')
    await fs.writeFile(join(root, 'active_kid'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_aes'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_sign'), '')
    await fs.mkdir(join(root, 'aes'), { recursive: true })
    await fs.mkdir(join(root, 'hmac'), { recursive: true })

    await fs.writeFile(join(root, 'aes', 'K1.b64u'), base64UrlEncode(Buffer.alloc(16)))
    await fs.writeFile(join(root, 'hmac', 'K1.b64u'), base64UrlEncode(Buffer.alloc(16)))
    const ks = new FileKeyStore({ directory: root })
    await expect(ks.reload()).rejects.toBeDefined()

    await fs.writeFile(join(root, 'aes', 'K1.b64u'), base64UrlEncode(Buffer.alloc(32)))
    await fs.writeFile(join(root, 'hmac', 'K1.b64u'), base64UrlEncode(Buffer.alloc(32)))
    await ks.reload()
    expect(() => ks.getSymmetricKey('AES-256-GCM', 'missing')).toThrow()
    expect(() => ks.getHmacKey('HMAC-SHA256', 'missing')).toThrow()
    expect(() => ks.getPrivateKey('Ed25519', 'missing')).toThrow()
    expect(() => ks.getPublicKey('Ed25519', 'missing')).toThrow()
  })

  it('loads PEM signing keys (Ed25519, RSA, P-256)', async () => {
    const root = await mkdtemp('fks3')
    await fs.writeFile(join(root, 'active_kid'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_aes'), '')
    await fs.writeFile(join(root, 'allowed_kids_sign'), 'K1')

    const { privateKey: edPriv, publicKey: edPub } = generateKeyPairSync('ed25519')
    await writePem(
      root,
      'ed25519/priv-K1.pem',
      edPriv.export({ format: 'pem', type: 'pkcs8' }).toString(),
    )
    await writePem(
      root,
      'ed25519/pub-K1.pem',
      edPub.export({ format: 'pem', type: 'spki' }).toString(),
    )

    const { privateKey: rsaPriv, publicKey: rsaPub } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
    })
    await writePem(
      root,
      'rsaps/priv-K1.pem',
      rsaPriv.export({ format: 'pem', type: 'pkcs1' }).toString(),
    )
    await writePem(
      root,
      'rsaps/pub-K1.pem',
      rsaPub.export({ format: 'pem', type: 'pkcs1' }).toString(),
    )

    const { privateKey: p256Priv, publicKey: p256Pub } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    })
    await writePem(
      root,
      'p256/priv-K1.pem',
      p256Priv.export({ format: 'pem', type: 'pkcs8' }).toString(),
    )
    await writePem(
      root,
      'p256/pub-K1.pem',
      p256Pub.export({ format: 'pem', type: 'spki' }).toString(),
    )

    const ks = new FileKeyStore({ directory: root })
    await ks.reload()

    expect(ks.getPrivateKey('Ed25519', 'K1')).toBeDefined()
    expect(ks.getPublicKey('Ed25519', 'K1')).toBeDefined()
    expect(ks.getPrivateKey('RSA-PSS-SHA256', 'K1')).toBeDefined()
    expect(ks.getPublicKey('RSA-PSS-SHA256', 'K1')).toBeDefined()
    expect(ks.getPrivateKey('P-256', 'K1')).toBeDefined()
    expect(ks.getPublicKey('P-256', 'K1')).toBeDefined()
  })

  it('warns and continues when optional directories missing', async () => {
    const root = await mkdtemp('fks4')
    await fs.writeFile(join(root, 'active_kid'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_aes'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_sign'), '')
    await fs.mkdir(join(root, 'aes'), { recursive: true })
    await fs.writeFile(join(root, 'aes', 'K1.b64u'), base64UrlEncode(Buffer.alloc(32)))

    const warnings: Array<{ path: string }> = []
    const logger = {
      warn: (msg: string, meta?: Record<string, unknown>) => {
        warnings.push({ path: (meta?.error as string) ?? msg })
      },
    }

    const ks = new FileKeyStore({ directory: root, logger: logger as Logger })
    await ks.reload()

    expect(ks.getSymmetricKey('AES-256-GCM', 'K1')).toBeDefined()
    expect(warnings.length).toBeGreaterThan(0)
  })

  it('handles concurrent reload calls safely', async () => {
    const root = await mkdtemp('fks-concurrent')
    await fs.writeFile(join(root, 'active_kid'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_aes'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_sign'), '')
    await fs.mkdir(join(root, 'aes'), { recursive: true })
    await fs.writeFile(join(root, 'aes', 'K1.b64u'), base64UrlEncode(Buffer.alloc(32)))
    await fs.mkdir(join(root, 'hmac'), { recursive: true })
    await fs.writeFile(join(root, 'hmac', 'K1.b64u'), base64UrlEncode(Buffer.alloc(32)))

    const ks = new FileKeyStore({ directory: root })

    // Call reload multiple times concurrently
    await Promise.all([ks.reload(), ks.reload(), ks.reload(), ks.reload()])

    // Should succeed without corruption
    expect(ks.getActiveKidFor('AES-256-GCM')).toBe('K1')
    expect(ks.getSymmetricKey('AES-256-GCM', 'K1')).toBeDefined()
    expect(ks.getHmacKey('HMAC-SHA256', 'K1')).toBeDefined()
  })

  it('rejects short HMAC key material with descriptive error', async () => {
    const root = await mkdtemp('fks-short-hmac')
    await fs.writeFile(join(root, 'active_kid'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_aes'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_sign'), '')
    await fs.mkdir(join(root, 'aes'), { recursive: true })
    await fs.mkdir(join(root, 'hmac'), { recursive: true })
    await fs.writeFile(join(root, 'aes', 'K1.b64u'), base64UrlEncode(Buffer.alloc(32)))
    await fs.writeFile(join(root, 'hmac', 'K1.b64u'), base64UrlEncode(Buffer.alloc(16)))
    const ks = new FileKeyStore({ directory: root })
    await expect(ks.reload()).rejects.toThrow('HMAC key must be >=32 bytes')
  })

  it('getAllowedKidsFor returns signing set for signing algorithms', async () => {
    const root = await mkdtemp('fks-signing-allowed')
    await fs.writeFile(join(root, 'active_kid'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_aes'), '')
    await fs.writeFile(join(root, 'allowed_kids_sign'), 'K1,K2')
    await fs.mkdir(join(root, 'ed25519'), { recursive: true })
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    await writePem(
      root,
      'ed25519/priv-K1.pem',
      privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    )
    await writePem(
      root,
      'ed25519/pub-K1.pem',
      publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    )

    const ks = new FileKeyStore({ directory: root })
    await ks.reload()
    expect(ks.getAllowedKidsFor('Ed25519')).toEqual(expect.arrayContaining(['K1', 'K2']))
  })

  it('throws UNSUPPORTED_ALG when requesting unknown algorithms', async () => {
    const root = await mkdtemp('fks-unsupported')
    await fs.writeFile(join(root, 'active_kid'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_aes'), 'K1')
    await fs.writeFile(join(root, 'allowed_kids_sign'), '')
    await fs.mkdir(join(root, 'aes'), { recursive: true })
    await fs.mkdir(join(root, 'hmac'), { recursive: true })
    await fs.writeFile(join(root, 'aes', 'K1.b64u'), base64UrlEncode(Buffer.alloc(32)))
    await fs.writeFile(join(root, 'hmac', 'K1.b64u'), base64UrlEncode(Buffer.alloc(32)))
    const ks = new FileKeyStore({ directory: root })
    await ks.reload()
    expect(() =>
      ks.getSymmetricKey(
        'AES-128-GCM' as unknown as import('../types/alg').SymmetricAlg,
        'K1',
      ),
    ).toThrow(CryptoError)
    expect(() =>
      ks.getHmacKey('HMAC-SHA1' as import('../types/alg').HmacAlg, 'K1'),
    ).toThrow(CryptoError)
  })
})
