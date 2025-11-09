import { Inject, Injectable } from '@nestjs/common'
import * as jose from 'jose'

import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'
import { KEY_STORE } from '../module/crypto.module'
import { canonicalStringify } from '../utils/canonical'
import { base64UrlEncode } from '../utils/encoding'

import type { KeyStore } from '../keystore/key-store'
import type { SignAlg } from '../types/alg'
import type { JwsAlg, JwsSignOptions, JwsVerifyOptions } from '../types/jose'
import type { CompactJWSHeaderParameters, JWSHeaderParameters, KeyLike } from 'jose'

/**
 * @summary JWS signing and verification using DI-managed keys.
 * @remarks
 * Uses `jose` compact JWS format with EdDSA (Ed25519), PS256 (RSA-PSS-SHA256), or ES256 (P-256 ECDSA).
 */
@Injectable()
export class JsonWebSignatureService {
  constructor(@Inject(KEY_STORE) private readonly keyStore: KeyStore) {}

  /**
   * @summary (Private) Import a private key for JWS signing.
   */
  private async importPrivateKey(alg: JwsAlg, kid: string): Promise<KeyLike> {
    if (alg === 'EdDSA') {
      const key = this.keyStore.getPrivateKey('Ed25519', kid)
      const pem = key.export({ format: 'pem', type: 'pkcs8' }).toString()
      return jose.importPKCS8(pem, 'EdDSA')
    }
    if (alg === 'PS256') {
      const key = this.keyStore.getPrivateKey('RSA-PSS-SHA256', kid)
      const pem = key.export({ format: 'pem', type: 'pkcs8' }).toString()
      return jose.importPKCS8(pem, 'PS256')
    }
    const key = this.keyStore.getPrivateKey('P-256', kid)
    const pem = key.export({ format: 'pem', type: 'pkcs8' }).toString()
    return jose.importPKCS8(pem, 'ES256')
  }

  /**
   * @summary (Private) Import a public key for JWS verification.
   */
  private async importPublicKey(alg: JwsAlg, kid: string): Promise<KeyLike> {
    if (alg === 'EdDSA') {
      const key = this.keyStore.getPublicKey('Ed25519', kid)
      const pem = key.export({ format: 'pem', type: 'spki' }).toString()
      return jose.importSPKI(pem, 'EdDSA')
    }
    if (alg === 'PS256') {
      const key = this.keyStore.getPublicKey('RSA-PSS-SHA256', kid)
      const pem = key.export({ format: 'pem', type: 'spki' }).toString()
      return jose.importSPKI(pem, 'PS256')
    }
    // ES256
    const key = this.keyStore.getPublicKey('P-256', kid)
    const pem = key.export({ format: 'pem', type: 'spki' }).toString()
    return jose.importSPKI(pem, 'ES256')
  }

  async sign(
    payload: Uint8Array | string | object,
    options?: JwsSignOptions,
  ): Promise<string> {
    /**
     * @summary Sign a payload as a compact JWS.
     * @param payload Bytes, string, or object.
     * @param options Algorithm (default EdDSA), kid, and protected header; `detached` to omit payload.
     * @returns Compact JWS string.
     * @throws {@link CryptoError} with code `KEY_NOT_FOUND` when keystore cannot provide the signing key.
     * @throws {@link CryptoError} with code `INPUT_VALIDATION_ERROR` when canonical option used with circular references.
     * @throws Error from `jose` library on signing failures.
     * @example
     * ```ts
     * const jws = await jwsSvc.sign({ hello: 'world' })
     * ```
     */
    const alg: JwsAlg = options?.alg ?? 'EdDSA'
    const ED25519: SignAlg = 'Ed25519'
    const RSA_PSS: SignAlg = 'RSA-PSS-SHA256'
    const P256: SignAlg = 'P-256'
    const family: SignAlg = alg === 'EdDSA' ? ED25519 : alg === 'PS256' ? RSA_PSS : P256
    const kid = options?.kid ?? this.keyStore.getActiveKidFor(family)
    const key = await this.importPrivateKey(alg, kid)
    const protectedHeader: CompactJWSHeaderParameters = {
      alg,
      kid,
      ...options?.protectedHeader,
    }

    const encoder = new TextEncoder()
    const payloadUint8: Uint8Array =
      payload instanceof Uint8Array
        ? payload
        : typeof payload === 'string'
          ? encoder.encode(payload)
          : encoder.encode(
              options?.canonical ? canonicalStringify(payload) : JSON.stringify(payload),
            )

    if (options?.detached) {
      const mode = options.detachedMode ?? 'compact-detached'
      if (mode === 'rfc7797') {
        const hdr: CompactJWSHeaderParameters = {
          ...protectedHeader,
          b64: false,
          crit: [...new Set([...(protectedHeader.crit ?? []), 'b64'])],
        }
        const jws = await new jose.CompactSign(payloadUint8)
          .setProtectedHeader(hdr)
          .sign(key)
        return jws
      }
      const jws = await new jose.CompactSign(payloadUint8)
        .setProtectedHeader(protectedHeader)
        .sign(key)
      const [h, _p, s] = jws.split('.')
      return `${h}..${s}`
    }

    return await new jose.CompactSign(payloadUint8)
      .setProtectedHeader(protectedHeader)
      .sign(key)
  }

  async verify(
    jws: string,
    options?: JwsVerifyOptions,
  ): Promise<{ payload: Uint8Array; protectedHeader: JWSHeaderParameters }> {
    /**
     * @summary Verify a compact JWS.
     * @param jws Compact JWS string.
     * @param options Optional expected algorithm and detached payload.
     * @returns Payload and protected header.
     * @throws {@link CryptoError} with code `INVALID_ENVELOPE` on algorithm mismatch.
     * @throws {@link CryptoError} with code `INPUT_VALIDATION_ERROR` when detached payload is missing.
     * @throws Error from `jose` library on signature verification failures.
     */
    const hdr = jose.decodeProtectedHeader(jws) as JWSHeaderParameters
    const alg = hdr.alg as JwsAlg
    if (options?.expectedAlg && options.expectedAlg !== alg) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_ENVELOPE,
        `Unexpected JWS alg (expected ${options.expectedAlg}, got ${alg})`,
      )
    }
    const kid = hdr.kid as string
    const key = await this.importPublicKey(alg, kid)
    const parts = jws.split('.')
    const isDetached = parts.length === 3 && parts[1] === ''
    const hasDetachedPayload = options?.detachedPayload !== undefined
    if (isDetached) {
      if (!hasDetachedPayload)
        throw new CryptoError(
          CryptoErrorCode.INPUT_VALIDATION_ERROR,
          'Detached JWS requires detachedPayload for verification',
        )
      const detachedBytes =
        typeof options?.detachedPayload === 'string'
          ? new TextEncoder().encode(options.detachedPayload)
          : (options?.detachedPayload as Uint8Array)
      const b64False = hdr.b64 === false
      if (b64False) {
        const { payload, protectedHeader } = await jose.flattenedVerify(
          {
            protected: parts[0],
            payload: detachedBytes,
            signature: parts[2],
          },
          key,
        )
        if (!protectedHeader) {
          throw new CryptoError(
            CryptoErrorCode.INVALID_ENVELOPE,
            'Invalid protected header in detached JWS',
          )
        }

        return { payload, protectedHeader }
      }
      const partsFull = [...parts]
      partsFull[1] = base64UrlEncode(detachedBytes)
      const reattached = partsFull.join('.')
      const { payload, protectedHeader } = await jose.compactVerify(reattached, key)
      return { payload, protectedHeader }
    }
    const { payload, protectedHeader } = await jose.compactVerify(jws, key)
    return { payload, protectedHeader }
  }
}
