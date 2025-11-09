/* eslint-disable unicorn/import-style -- convenience */
import { Buffer } from 'node:buffer'
import { createPrivateKey, createPublicKey, createSecretKey } from 'node:crypto'
import { promises as fs } from 'node:fs'
import { basename } from 'node:path'

import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'
import { base64UrlDecode } from '../utils/encoding'

import type { KeyStore } from './key-store'
import type { Alg, HmacAlg, SignAlg, SymmetricAlg } from '../types/alg'
import type { Logger } from '@nestjs/common'
import type { KeyObject } from 'node:crypto'

export interface FileKeyStoreOptions {
  directory: string
  logger?: Logger
}

/**
 * @summary Safely read a file, returning undefined on error.
 * @param path Path to the file.
 * @param logger Optional logger for warnings.
 * @returns File contents as UTF-8 string, or undefined if read fails.
 */
async function safeReadFile(path: string, logger?: Logger): Promise<string | undefined> {
  try {
    return await fs.readFile(path, 'utf8')
  } catch (error) {
    logger?.warn(`Failed to read file ${path}`, {
      error: error instanceof Error ? error.message : String(error),
    })
    return undefined
  }
}

/**
 * @summary Safely list directory contents, returning empty array on error.
 * @param path Path to the directory.
 * @param logger Optional logger for warnings.
 * @returns Array of file/directory names, or empty array if listing fails.
 */
async function listDir(path: string, logger?: Logger): Promise<string[]> {
  try {
    return await fs.readdir(path)
  } catch (error) {
    logger?.warn(`Failed to list directory ${path}`, {
      error: error instanceof Error ? error.message : String(error),
    })
    return []
  }
}

/**
 * @summary Keystore that sources key material from a filesystem directory.
 * @remarks
 * Expects a simple layout with `active_kid`, `allowed_kids_*`, and per-algorithm
 * subdirectories containing PEM or base64url-encoded key files. Call {@link reload}
 * to load or refresh material from disk.
 */
export class FileKeyStore implements KeyStore {
  private activeKid = ''

  private allowedKidsAes = new Set<string>()

  private allowedKidsSign = new Set<string>()

  private symmetricKeys = new Map<string, KeyObject>()

  private hmacKeys = new Map<string, KeyObject>()

  private privKeys = new Map<string, KeyObject>()

  private pubKeys = new Map<string, KeyObject>()

  private reloadPromise: Promise<void> | null = null

  /**
   * @summary Create a file-backed keystore.
   * @param options Directory and optional logger for warning emissions.
   */
  constructor(private readonly options: FileKeyStoreOptions) {}

  /**
   * @summary Load key material from disk according to the configured directory layout.
   * @remarks
   * This method is safe to call concurrently. If a reload is already in progress,
   * subsequent calls will wait for the current reload to complete.
   * @throws {@link CryptoError} when required files are missing or contain invalid key bytes.
   */
  async reload(): Promise<void> {
    // If reload is already in progress, wait for it
    if (this.reloadPromise) {
      await this.reloadPromise
      return
    }

    // Create new reload promise
    this.reloadPromise = this.doReload()

    try {
      await this.reloadPromise
    } finally {
      this.reloadPromise = null
    }
  }

  /**
   * @summary Internal reload implementation.
   * @private
   */
  private async doReload(): Promise<void> {
    const root = this.options.directory
    const logger = this.options.logger
    const activeKidFile = await safeReadFile(`${root}/active_kid`, logger)
    if (!activeKidFile)
      throw new CryptoError(CryptoErrorCode.CONFIG_ERROR, 'Missing active_kid file')
    const activeKid = activeKidFile.trim()
    const allowedAesFile = (await safeReadFile(`${root}/allowed_kids_aes`, logger)) ?? ''
    const allowedSignFile =
      (await safeReadFile(`${root}/allowed_kids_sign`, logger)) ?? ''
    const allowedKidsAes = new Set([
      ...allowedAesFile
        .split(',')
        .map(s => s.trim())
        .filter(Boolean),
      activeKid,
    ])
    const allowedKidsSign = new Set([
      ...allowedSignFile
        .split(',')
        .map(s => s.trim())
        .filter(Boolean),
      activeKid,
    ])

    const symmetricKeys = new Map<string, KeyObject>()
    const hmacKeys = new Map<string, KeyObject>()
    const privKeys = new Map<string, KeyObject>()
    const pubKeys = new Map<string, KeyObject>()

    for (const file of await listDir(`${root}/aes`, logger)) {
      const name = basename(file)
      const kid = name.replace(/\.[^.]+$/, '')
      const content = await safeReadFile(`${root}/aes/${file}`, logger)
      if (!content) continue
      const keyBytes = base64UrlDecode(content.trim())
      if (keyBytes.length !== 32) {
        throw new CryptoError(
          CryptoErrorCode.INVALID_KEY_MATERIAL,
          'AES key must be 32 bytes',
          { kid },
        )
      }
      symmetricKeys.set(kid, createSecretKey(Buffer.from(keyBytes)))
    }

    for (const file of await listDir(`${root}/hmac`, logger)) {
      const name = basename(file)
      const kid = name.replace(/\.[^.]+$/, '')
      const content = await safeReadFile(`${root}/hmac/${file}`, logger)
      if (!content) continue
      const keyBytes = base64UrlDecode(content.trim())

      if (keyBytes.length < 32) {
        throw new CryptoError(
          CryptoErrorCode.INVALID_KEY_MATERIAL,
          'HMAC key must be >=32 bytes',
          { kid },
        )
      }
      hmacKeys.set(kid, createSecretKey(Buffer.from(keyBytes)))
    }

    for (const file of await listDir(`${root}/ed25519`, logger)) {
      const name = basename(file)
      const [kind, kid] = name.startsWith('priv-')
        ? ['priv', name.slice(5).replace(/\.pem$/, '')]
        : name.startsWith('pub-')
          ? ['pub', name.slice(4).replace(/\.pem$/, '')]
          : [undefined, undefined]
      if (!kind || !kid) continue
      const content = await safeReadFile(`${root}/ed25519/${file}`, logger)
      if (!content) continue
      if (kind === 'priv') privKeys.set(`Ed25519:${kid}`, createPrivateKey(content))
      else pubKeys.set(`Ed25519:${kid}`, createPublicKey(content))
    }

    for (const file of await listDir(`${root}/rsaps`, logger)) {
      const name = basename(file)
      const [kind, kid] = name.startsWith('priv-')
        ? ['priv', name.slice(5).replace(/\.pem$/, '')]
        : name.startsWith('pub-')
          ? ['pub', name.slice(4).replace(/\.pem$/, '')]
          : [undefined, undefined]
      if (!kind || !kid) continue
      const content = await safeReadFile(`${root}/rsaps/${file}`, logger)
      if (!content) continue
      if (kind === 'priv')
        privKeys.set(`RSA-PSS-SHA256:${kid}`, createPrivateKey(content))
      else pubKeys.set(`RSA-PSS-SHA256:${kid}`, createPublicKey(content))
    }

    for (const file of await listDir(`${root}/p256`, logger)) {
      const name = basename(file)
      const [kind, kid] = name.startsWith('priv-')
        ? ['priv', name.slice(5).replace(/\.pem$/, '')]
        : name.startsWith('pub-')
          ? ['pub', name.slice(4).replace(/\.pem$/, '')]
          : [undefined, undefined]
      if (!kind || !kid) continue
      const content = await safeReadFile(`${root}/p256/${file}`, logger)
      if (!content) continue
      if (kind === 'priv') privKeys.set(`P-256:${kid}`, createPrivateKey(content))
      else pubKeys.set(`P-256:${kid}`, createPublicKey(content))
    }

    this.activeKid = activeKid
    this.allowedKidsAes = allowedKidsAes
    this.allowedKidsSign = allowedKidsSign
    this.symmetricKeys = symmetricKeys
    this.hmacKeys = hmacKeys
    this.privKeys = privKeys
    this.pubKeys = pubKeys
  }

  /**
   * @summary Return the active key identifier for the requested algorithm family.
   */
  getActiveKidFor(_alg: Alg): string {
    return this.activeKid
  }

  /**
   * @summary List allowed key identifiers for the supplied algorithm family.
   */
  getAllowedKidsFor(alg: Alg): string[] {
    if (alg === 'AES-256-GCM' || alg === 'HMAC-SHA256') return [...this.allowedKidsAes]
    return [...this.allowedKidsSign]
  }

  /**
   * @summary Retrieve an AES-256-GCM key.
   * @throws {@link CryptoError} with code `UNSUPPORTED_ALG` or `KEY_NOT_FOUND` when the
   * request cannot be fulfilled.
   */
  getSymmetricKey(alg: SymmetricAlg, kid: string): KeyObject {
    if (alg !== 'AES-256-GCM')
      throw new CryptoError(
        CryptoErrorCode.UNSUPPORTED_ALG,
        `Unsupported symmetric alg: ${alg}`,
      )
    const key = this.symmetricKeys.get(kid)
    if (!key)
      throw new CryptoError(CryptoErrorCode.KEY_NOT_FOUND, 'AES key not found', { kid })
    return key
  }

  /**
   * @summary Retrieve an HMAC-SHA256 key.
   * @throws {@link CryptoError} with code `UNSUPPORTED_ALG` or `KEY_NOT_FOUND` when missing.
   */
  getHmacKey(alg: HmacAlg, kid: string): KeyObject {
    if (alg !== 'HMAC-SHA256')
      throw new CryptoError(
        CryptoErrorCode.UNSUPPORTED_ALG,
        `Unsupported HMAC alg: ${alg}`,
      )
    const key = this.hmacKeys.get(kid)
    if (!key)
      throw new CryptoError(CryptoErrorCode.KEY_NOT_FOUND, 'HMAC key not found', { kid })
    return key
  }

  /**
   * @summary Retrieve a private signing key for the given algorithm and key id.
   * @throws {@link CryptoError} with code `KEY_NOT_FOUND` when unavailable.
   */
  getPrivateKey(alg: SignAlg, kid: string): KeyObject {
    const key = this.privKeys.get(`${alg}:${kid}`)
    if (!key)
      throw new CryptoError(CryptoErrorCode.KEY_NOT_FOUND, 'Private key not found', {
        alg,
        kid,
      })
    return key
  }

  /**
   * @summary Retrieve a public verification key for the given algorithm and key id.
   * @throws {@link CryptoError} with code `KEY_NOT_FOUND` when unavailable.
   */
  getPublicKey(alg: SignAlg, kid: string): KeyObject {
    const key = this.pubKeys.get(`${alg}:${kid}`)
    if (!key)
      throw new CryptoError(CryptoErrorCode.KEY_NOT_FOUND, 'Public key not found', {
        alg,
        kid,
      })
    return key
  }
}
