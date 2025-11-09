import { Inject, Injectable, Optional } from '@nestjs/common'
import * as jose from 'jose'

import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'
import { KEY_STORE } from '../module/crypto.module'

import type { KeyStore } from '../keystore/key-store'
import type { SignAlg } from '../types/alg'
import type { JwtSignOptions, JwtVerifyOptions, JwsAlg } from '../types/jose'
import type { Logger } from '@nestjs/common'
import type { JWSHeaderParameters, KeyLike } from 'jose'

const DEFAULT_EXPIRATION = '15m'
type TimeUnit = 'ms' | 's' | 'm' | 'h' | 'd'

function normalizeExpiration(input?: string | number): string | number {
  if (input === undefined) return DEFAULT_EXPIRATION
  if (typeof input === 'number') return input

  const trimmed = input.trim()
  if (!trimmed) return DEFAULT_EXPIRATION

  const match = /^(\d+(?:\.\d+)?)(ms|[smhd])$/i.exec(trimmed)
  if (!match) return trimmed

  const value = Number(match[1])
  const unit = match[2].toLowerCase() as TimeUnit

  if (!Number.isFinite(value)) return trimmed

  if (unit === 'ms') {
    const seconds = value / 1000
    const normalizedSeconds = Number.isInteger(seconds)
      ? seconds.toString(10)
      : seconds.toString()
    return `${normalizedSeconds}s`
  }

  const normalizedValue = Number.isInteger(value) ? value.toString(10) : value.toString()

  return `${normalizedValue}${unit}`
}

/**
 * @summary JWT signing and verification utilities backed by the configured keystore.
 * @remarks
 * Resolves private/public keys from the injected {@link KeyStore} and delegates JWS/JWT
 * operations to the `jose` library. Supports EdDSA (Ed25519), PS256 (RSA-PSS-SHA256),
 * and ES256 (P-256) algorithms, optional remote JWKS verification, and structured
 * options for clock skew, required claims, and issuer/audience enforcement.
 */
@Injectable()
export class JsonWebTokenService {
  constructor(
    @Inject(KEY_STORE) private readonly keyStore: KeyStore,
    @Optional() private readonly logger?: Logger,
  ) {}

  /**
   * @summary Import a private key for the requested JWS algorithm.
   * @param alg Target signing algorithm. Must be one of `EdDSA`, `PS256`, or `ES256`.
   * @param kid Key identifier resolved from the keystore.
   * @throws {@link CryptoError} if the keystore cannot supply the requested key.
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
   * @summary Import a public key for the requested JWS algorithm.
   * @param alg Verification algorithm (`EdDSA`, `PS256`, or `ES256`).
   * @param kid Key identifier resolved from the keystore.
   * @throws {@link CryptoError} if the keystore cannot supply the requested key.
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
    const key = this.keyStore.getPublicKey('P-256', kid)
    const pem = key.export({ format: 'pem', type: 'spki' }).toString()
    return jose.importSPKI(pem, 'ES256')
  }

  /**
   * @summary Sign claims into a compact JWT.
   * @param claims Arbitrary payload claims. Standard JWT claims can be provided via
   * `options` (e.g., issuer, audience) rather than duplicating values here.
   * @param options Optional signing options controlling algorithm, key id, token header,
   * expiration, issuer/audience/subject, and custom header fields.
   * @returns A compact JWT string containing the signed payload.
   * @throws {@link CryptoError} if the required private key cannot be obtained from the
   * keystore or if key import fails.
   */
  async sign(claims: Record<string, unknown>, options?: JwtSignOptions): Promise<string> {
    const alg: JwsAlg = options?.alg ?? 'EdDSA'
    const ED25519: SignAlg = 'Ed25519'
    const RSA_PSS: SignAlg = 'RSA-PSS-SHA256'
    const P256: SignAlg = 'P-256'
    const family: SignAlg = alg === 'EdDSA' ? ED25519 : alg === 'PS256' ? RSA_PSS : P256
    const kid = options?.kid ?? this.keyStore.getActiveKidFor(family)
    const key = await this.importPrivateKey(alg, kid)
    const jwtBuilder = new jose.SignJWT(claims as jose.JWTPayload)
      .setProtectedHeader({ alg, kid, typ: options?.typ ?? 'JWT', ...options?.header })
      .setIssuedAt()
      .setExpirationTime(normalizeExpiration(options?.expiresIn))
    if (options?.subject) jwtBuilder.setSubject(options.subject)
    if (options?.issuer) jwtBuilder.setIssuer(options.issuer)
    if (options?.audience) jwtBuilder.setAudience(options.audience)
    const jwt = await jwtBuilder.sign(key)
    return jwt
  }

  /**
   * @summary Verify a compact JWT using remote JWKS (if configured) or local keystore keys.
   * @param token JWT string to verify.
   * @param options Optional verification controls: acceptable algorithms, issuer/audience
   * expectations, detached JWKS sources (`jwks`, `jwksUrls`, `issuerJwks`), clock skew, and
   * required claims. Set `requireRemoteJwks` to fail when remote resolution cannot be
   * satisfied.
   * @returns The decoded payload and protected header on successful verification.
   * @throws {@link CryptoError} when algorithm expectations fail or keystore keys are
   * unavailable. Propagates network errors encountered while resolving remote JWKS when no
   * fallback is permitted.
   */
  async verify(
    token: string,
    options?: JwtVerifyOptions,
  ): Promise<{ payload: Record<string, unknown>; header: JWSHeaderParameters }> {
    const hdr = jose.decodeProtectedHeader(token)
    const alg = hdr.alg as JwsAlg
    const kid = hdr.kid
    if (!kid) {
      throw new CryptoError(
        CryptoErrorCode.INVALID_ENVELOPE,
        'JWT header missing required kid field',
      )
    }

    const algorithms = options?.algs ?? ['EdDSA', 'PS256', 'ES256']
    const maxTokenAge = undefined
    const clockTolerance = `${options?.maxSkew ?? 60}s`

    const verifyWithKey = async (key: KeyLike): ReturnType<typeof jose.jwtVerify> =>
      jose.jwtVerify(token, key, {
        algorithms,
        issuer: options?.issuer,
        audience: options?.audience,
        subject: options?.subject,
        clockTolerance,
        maxTokenAge,
        requiredClaims:
          options?.requiredClaims ?? ((options?.requireExp ?? true) ? ['exp'] : []),
      }) as unknown as ReturnType<typeof jose.jwtVerify>

    if (options?.jwks) {
      const jwks = jose.createLocalJWKSet(options.jwks as jose.JSONWebKeySet)
      const { payload, protectedHeader } = await jose.jwtVerify(token, jwks, {
        algorithms,
        issuer: options?.issuer,
        audience: options?.audience,
        subject: options?.subject,
        clockTolerance,
        maxTokenAge,
        requiredClaims:
          options?.requiredClaims ?? ((options?.requireExp ?? true) ? ['exp'] : []),
      })
      return {
        payload: payload as unknown as Record<string, unknown>,
        header: protectedHeader,
      }
    }

    const makeRemote = (url: string): ReturnType<typeof jose.createRemoteJWKSet> =>
      jose.createRemoteJWKSet(new URL(url), {
        timeoutDuration: options?.timeoutMs ?? 3000,
        cooldownDuration: (options?.cacheTtlSeconds ?? 300) * 1000,
      })

    if (options?.issuerJwks && options.issuerJwks.length > 0) {
      for (const entry of options.issuerJwks) {
        try {
          const jwks = makeRemote(entry.jwksUrl)
          const { payload, protectedHeader } = await jose.jwtVerify(token, jwks, {
            algorithms,
            issuer: options?.issuer ?? entry.issuer,
            audience: options?.audience,
            subject: options?.subject,
            clockTolerance,
            maxTokenAge,
            requiredClaims:
              options?.requiredClaims ?? ((options?.requireExp ?? true) ? ['exp'] : []),
          })
          return {
            payload: payload as unknown as Record<string, unknown>,
            header: protectedHeader,
          }
        } catch (error) {
          this.logger?.warn('Remote JWKS verification failed', {
            issuer: entry.issuer,
            jwksUrl: entry.jwksUrl,
            error: error instanceof Error ? error.message : String(error),
          })
        }
      }
    }

    if (options?.jwksUrls && options.jwksUrls.length > 0) {
      for (const u of options.jwksUrls) {
        try {
          const jwks = makeRemote(u)
          const { payload, protectedHeader } = await jose.jwtVerify(token, jwks, {
            algorithms,
            issuer: options?.issuer,
            audience: options?.audience,
            subject: options?.subject,
            clockTolerance,
            maxTokenAge,
            requiredClaims:
              options?.requiredClaims ?? ((options?.requireExp ?? true) ? ['exp'] : []),
          })
          return {
            payload: payload as unknown as Record<string, unknown>,
            header: protectedHeader,
          }
        } catch (error) {
          this.logger?.warn('Remote JWKS verification failed', {
            jwksUrl: u,
            error: error instanceof Error ? error.message : String(error),
          })
        }
      }
    }

    if (options?.jwksUrls || options?.issuerJwks) {
      if (options.requireRemoteJwks) {
        throw new Error('Remote JWKS verification required but all attempts failed')
      }
      this.logger?.warn(
        'All remote JWKS verification attempts failed, falling back to local keystore',
      )
    }

    const key = await this.importPublicKey(alg, kid)
    const { payload, protectedHeader } = await verifyWithKey(key)
    return {
      payload: payload as unknown as Record<string, unknown>,
      header: protectedHeader,
    }
  }
}
