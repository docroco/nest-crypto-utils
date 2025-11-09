import { Buffer } from 'node:buffer'
import { createSign, createVerify, sign, verify, constants } from 'node:crypto'

import { Inject, Injectable } from '@nestjs/common'

import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'
import { CRYPTO_OPTIONS, KEY_STORE } from '../module/crypto.module'
import { toBytes } from '../utils/bytes'
import { base64UrlEncode, base64UrlDecode } from '../utils/encoding'
import { assertMaxSize } from '../utils/validation'

import type { CryptoModuleOptions } from '../config/crypto.options'
import type { KeyStore } from '../keystore/key-store'
import type { SignAlg } from '../types/alg'
import type { SignatureV1 } from '../types/envelope'

/**
 * @summary Detached signature utilities for Ed25519, RSA-PSS-SHA256, and P-256 (ECDSA).
 * @remarks
 * Produces and verifies base64url-encoded signatures with algorithm and kid metadata.
 */
@Injectable()
export class SigningService {
  constructor(
    @Inject(KEY_STORE) private readonly keyStore: KeyStore,
    @Inject(CRYPTO_OPTIONS) private readonly options: CryptoModuleOptions,
  ) {}

  async sign(
    input: string | Uint8Array,
    options?: { kid?: string; alg?: SignAlg },
  ): Promise<SignatureV1> {
    /**
     * @summary Sign input using the selected algorithm.
     * @param input Input message as `string | Uint8Array`.
     * @param options Optional key id and algorithm (`Ed25519` default, `RSA-PSS-SHA256`, or `P-256`).
     * @returns Signature envelope with base64url-encoded signature.
     * @throws {@link CryptoError} with code `UNSUPPORTED_ALG` for unsupported algorithms.
     */
    const alg = options?.alg ?? 'Ed25519'
    const kid = options?.kid ?? this.keyStore.getActiveKidFor(alg)

    const inputBytes = toBytes(input)
    const maxSize = this.options.maxSigningInputSize ?? 10 * 1024 * 1024
    assertMaxSize('signing input', inputBytes, maxSize)

    const data = Buffer.from(inputBytes)

    if (alg === 'Ed25519') {
      const key = this.keyStore.getPrivateKey('Ed25519', kid)
      const sig = sign(null, data, key)
      return { v: '1', alg, kid, sig: base64UrlEncode(sig) }
    }

    if (alg === 'RSA-PSS-SHA256') {
      const key = this.keyStore.getPrivateKey('RSA-PSS-SHA256', kid)
      const signer = createSign('sha256')
      signer.update(data)
      signer.end()
      const sig = signer.sign({
        key,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      })
      return { v: '1', alg, kid, sig: base64UrlEncode(sig) }
    }

    if (alg === 'P-256') {
      const key = this.keyStore.getPrivateKey('P-256', kid)
      const sig = sign(null, data, key)
      return { v: '1', alg, kid, sig: base64UrlEncode(sig) }
    }

    throw new CryptoError(
      CryptoErrorCode.UNSUPPORTED_ALG,
      `Unsupported signing alg: ${alg}`,
    )
  }

  async verify(input: string | Uint8Array, signature: SignatureV1): Promise<boolean> {
    /**
     * @summary Verify a signature envelope.
     * @param input Original message.
     * @param signature Signature envelope produced by {@link sign}.
     * @returns True when signature verifies; false otherwise.
     * @throws {@link CryptoError} with code `UNSUPPORTED_ALG` for unsupported algorithms.
     */
    const { alg, kid, sig } = signature
    const data = Buffer.from(toBytes(input))
    const sigBytes = Buffer.from(base64UrlDecode(sig))

    if (alg === 'Ed25519') {
      const key = this.keyStore.getPublicKey('Ed25519', kid)
      return verify(null, data, key, sigBytes)
    }

    if (alg === 'RSA-PSS-SHA256') {
      const key = this.keyStore.getPublicKey('RSA-PSS-SHA256', kid)
      const verifier = createVerify('sha256')
      verifier.update(data)
      verifier.end()
      return verifier.verify(
        { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
        sigBytes,
      )
    }

    if (alg === 'P-256') {
      const key = this.keyStore.getPublicKey('P-256', kid)
      return verify(null, data, key, sigBytes)
    }

    throw new CryptoError(
      CryptoErrorCode.UNSUPPORTED_ALG,
      `Unsupported signing alg: ${alg}`,
    )
  }
}
