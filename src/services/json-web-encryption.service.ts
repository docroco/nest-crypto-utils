import { Inject, Injectable } from '@nestjs/common'
import * as jose from 'jose'

import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'
import { KEY_STORE } from '../module/crypto.module'

import type { KeyStore } from '../keystore/key-store'
import type { SignAlg } from '../types/alg'
import type { JweAlg, JweDecryptOptions, JweEncryptOptions, JweEnc } from '../types/jose'
import type { KeyLike } from 'jose'

/**
 * @summary JWE encrypt/decrypt using RSA-OAEP-256 or ECDH-ES(+-A256KW) for key management and A256GCM for content.
 * @remarks
 * Wraps `jose` to encrypt small payloads directly. Prefer envelope encryption for large data.
 */
@Injectable()
export class JsonWebEncryptionService {
  constructor(@Inject(KEY_STORE) private readonly keyStore: KeyStore) {}

  /**
   * @summary (Private) Import an RSA public key for JWE encryption.
   */
  private async importPublicKeyForEncrypt(kid: string): Promise<KeyLike> {
    const key = this.keyStore.getPublicKey('RSA-PSS-SHA256', kid)
    const pem = key.export({ format: 'pem', type: 'spki' }).toString()
    return jose.importSPKI(pem, 'RSA-OAEP-256')
  }

  /**
   * @summary (Private) Import an RSA private key for JWE decryption.
   */
  private async importPrivateKeyForDecrypt(kid: string): Promise<KeyLike> {
    const key = this.keyStore.getPrivateKey('RSA-PSS-SHA256', kid)
    const pem = key.export({ format: 'pem', type: 'pkcs8' }).toString()
    return jose.importPKCS8(pem, 'RSA-OAEP-256')
  }

  private async importP256PublicKeyForEncrypt(kid: string): Promise<KeyLike> {
    const key = this.keyStore.getPublicKey('P-256', kid)
    const pem = key.export({ format: 'pem', type: 'spki' }).toString()
    return jose.importSPKI(pem, 'ECDH-ES')
  }

  private async importP256PrivateKeyForDecrypt(kid: string): Promise<KeyLike> {
    const key = this.keyStore.getPrivateKey('P-256', kid)
    const pem = key.export({ format: 'pem', type: 'pkcs8' }).toString()
    return jose.importPKCS8(pem, 'ECDH-ES')
  }

  async encrypt(
    plaintext: Uint8Array | string,
    options?: JweEncryptOptions,
  ): Promise<string> {
    /**
     * @summary Encrypt plaintext into a compact JWE using RSA-OAEP-256/A256GCM.
     * @param plaintext Bytes or UTF-8 string.
     * @param options JWE header options: alg (default RSA-OAEP-256), enc (default A256GCM), kid, and zip.
     * @returns Compact JWE string.
     * @throws {@link CryptoError} with code `KEY_NOT_FOUND` when keystore cannot provide the encryption key.
     * @throws Error from `jose` library on encryption failures.
     */
    const alg: JweAlg = options?.alg ?? 'RSA-OAEP-256'
    const enc: JweEnc = options?.enc ?? 'A256GCM'
    const RSA_PSS: SignAlg = 'RSA-PSS-SHA256'
    const P256: SignAlg = 'P-256'
    const family: SignAlg = alg === 'RSA-OAEP-256' ? RSA_PSS : P256
    const kid = options?.kid ?? this.keyStore.getActiveKidFor(family)
    const publicKey =
      alg === 'RSA-OAEP-256'
        ? await this.importPublicKeyForEncrypt(kid)
        : await this.importP256PublicKeyForEncrypt(kid)
    const protectedHeader = {
      alg,
      enc,
      kid,
      ...(options?.zip ? { zip: options.zip } : {}),
    }
    const pt =
      typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext
    return new jose.CompactEncrypt(pt)
      .setProtectedHeader(protectedHeader)
      .encrypt(publicKey)
  }

  async decrypt(jwe: string, options?: JweDecryptOptions): Promise<Uint8Array> {
    /**
     * @summary Decrypt a compact JWE.
     * @param jwe Compact JWE string.
     * @param options Optional expected alg/enc to assert.
     * @returns Decrypted plaintext bytes.
     * @throws {@link CryptoError} with code `INVALID_ENVELOPE` on alg/enc mismatch or decryption failures.
     */
    const protectedHeader = jose.decodeProtectedHeader(jwe) as jose.JWEHeaderParameters
    const alg = protectedHeader.alg as JweAlg
    const enc = protectedHeader.enc as JweEnc
    if (
      (options?.expectedAlg && options.expectedAlg !== alg) ||
      (options?.expectedEnc && options.expectedEnc !== enc)
    ) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_ENVELOPE,
        `Unexpected JWE alg/enc (expected ${options?.expectedAlg ?? 'any'}/${options?.expectedEnc ?? 'any'}, got ${alg}/${enc})`,
      )
    }
    const kid = protectedHeader.kid as string
    const privateKey =
      alg === 'RSA-OAEP-256'
        ? await this.importPrivateKeyForDecrypt(kid)
        : await this.importP256PrivateKeyForDecrypt(kid)
    const { plaintext } = await jose.compactDecrypt(jwe, privateKey)
    return new Uint8Array(plaintext)
  }
}
