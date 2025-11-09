import { generateKeyPairSync } from 'node:crypto'

import { decodeJwt } from 'jose'

import { CryptoErrorCode } from '../errors/crypto.error'
import { EnvKeyStore } from '../keystore/env-key-store'

import { JsonWebTokenService } from './json-web-token.service'

import type { Logger } from '@nestjs/common'

function withEnv<T>(vars: Record<string, string>, fn: () => T): T {
  const old = { ...process.env }
  Object.assign(process.env, vars)
  try {
    return fn()
  } finally {
    process.env = old
  }
}

describe('JsonWebTokenService', () => {
  it('signs and verifies JWT with EdDSA', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign(
        { role: 'user' },
        { expiresIn: '5m', issuer: 'me', audience: 'you' },
      )
      const out = await svc.verify(jwt, { issuer: 'me', audience: 'you' })
      expect(out.payload.role).toBe('user')
    })
  })

  it('signs and verifies JWT with ES256', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    })
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_P256_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_P256_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign(
        { role: 'user' },
        { alg: 'ES256', expiresIn: '5m', issuer: 'me', audience: 'you' },
      )
      const out = await svc.verify(jwt, { issuer: 'me', audience: 'you' })
      expect(out.payload.role).toBe('user')
    })
  })

  it('signs and verifies JWT with PS256', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_RSAPS_PRIV_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
      [`CRYPTO_RSAPS_PUB_${kid}`]: publicKey
        .export({ format: 'pem', type: 'pkcs1' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign(
        { role: 'user' },
        { alg: 'PS256', expiresIn: '5m', issuer: 'me', audience: 'you' },
      )
      const out = await svc.verify(jwt, { issuer: 'me', audience: 'you' })
      expect(out.payload.role).toBe('user')
    })
  })

  it('verifies via local JWKS (in-memory JWK) with matching kid', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: 'test' }, { issuer: 'me', audience: 'you' })

      const jose = await import('jose')
      const spki = publicKey.export({ format: 'pem', type: 'spki' }).toString()
      const keyLike = await jose.importSPKI(spki, 'EdDSA')
      const jwk = await jose.exportJWK(keyLike)
      ;(jwk as unknown as Record<string, unknown>).kid = kid

      const out = await svc.verify(jwt, {
        jwks: { keys: [jwk] as unknown[] },
        issuer: 'me',
        audience: 'you',
      })
      expect(out.payload.data).toBe('test')
    })
  })

  it('respects algorithms filtering', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ ok: true })

      // Wrong allowed algs should fail
      await expect(svc.verify(jwt, { algs: ['ES256'] })).rejects.toBeDefined()

      // Correct allowed algs should pass
      const out = await svc.verify(jwt, { algs: ['EdDSA'] })
      expect(out.payload.ok).toBe(true)
    })
  })

  it('emits future exp when using relative expiresIn values', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const before = Math.floor(Date.now() / 1000)
      const jwt = await svc.sign({ role: 'tester' }, { expiresIn: '10s' })
      const decoded = decodeJwt(jwt)
      expect(typeof decoded.exp).toBe('number')
      expect(decoded.exp as number).toBeGreaterThan(before)
    })
  })

  it('normalises numeric expiresIn values', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: true }, { expiresIn: 120 })
      const decoded = decodeJwt(jwt)
      expect(decoded.exp).toBe(120)
    })
  })

  it('normalises millisecond expiresIn values', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: true }, { expiresIn: '500ms' })
      const decoded = decodeJwt(jwt)
      const exp = decoded.exp as number
      const iat = decoded.iat as number
      expect(exp - iat).toBeGreaterThan(0)
      expect(exp - iat).toBeLessThanOrEqual(1)
    })
  })

  it('falls back to default expiration when expiresIn is blank', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ foo: 'bar' }, { expiresIn: '   ' })
      const decoded = decodeJwt(jwt)
      expect(decoded.exp).toBeDefined()
    })
  })

  it('verifies via remote JWKS (mocked) using jwksUrls', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ x: 1 }, { issuer: 'me', audience: 'you' })

      const jose = await import('jose')
      const spy = jest
        .spyOn(jose, 'createRemoteJWKSet')
        .mockReturnValue(
          (async () =>
            publicKey as unknown as import('jose').KeyLike) as unknown as ReturnType<
            typeof jest.spyOn
          >,
        ) as unknown as ReturnType<typeof jest.spyOn>

      const out = await svc.verify(jwt, {
        jwksUrls: ['https://example.com/jwks.json'],
        issuer: 'me',
        audience: 'you',
      })
      expect(out.payload.x).toBe(1)
      spy.mockRestore()
    })
  })

  it('verifies via issuerJwks when remote JWKS succeeds', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ value: 42 }, { issuer: 'issuer-a', audience: 'aud' })

      const jose = await import('jose')
      const spy = jest
        .spyOn(jose, 'createRemoteJWKSet')
        .mockReturnValue(
          (async () =>
            publicKey as unknown as import('jose').KeyLike) as unknown as ReturnType<
            typeof jest.spyOn
          >,
        ) as unknown as ReturnType<typeof jest.spyOn>

      const out = await svc.verify(jwt, {
        issuerJwks: [{ issuer: 'issuer-a', jwksUrl: 'https://issuer.example/jwks' }],
      })
      expect(out.payload.value).toBe(42)
      spy.mockRestore()
    })
  })

  it('remote JWKS failure falls back to local keystore', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ y: 2 }, { issuer: 'me', audience: 'you' })

      const jose = await import('jose')
      const spy = jest.spyOn(jose, 'createRemoteJWKSet').mockImplementation(
        () =>
          (async () => {
            throw new Error('network')
          }) as unknown as ReturnType<typeof jest.spyOn>,
      )

      const out = await svc.verify(jwt, {
        jwksUrls: ['https://bad.example/jwks.json'],
        issuer: 'me',
        audience: 'you',
      })
      expect(out.payload.y).toBe(2)
      spy.mockRestore()
    })
  })

  it('handles JWT without kid in header gracefully', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)

      // Create JWT manually without kid
      const jose = await import('jose')
      const key = await jose.importPKCS8(
        privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
        'EdDSA',
      )

      const jwtWithoutKid = await new jose.SignJWT({ data: 'test' })
        .setProtectedHeader({ alg: 'EdDSA' }) // No kid field
        .setExpirationTime('5m')
        .sign(key)

      // Should fail with INVALID_ENVELOPE error
      await expect(svc.verify(jwtWithoutKid)).rejects.toMatchObject({
        code: CryptoErrorCode.INVALID_ENVELOPE,
        message: expect.stringContaining('kid'),
      })
    })
  })
})

describe('JsonWebTokenService expiration and claims', () => {
  it('rejects expired JWT', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: 'test' }, { expiresIn: '1ms' })
      await new Promise(resolve => {
        setTimeout(resolve, 10)
      })

      await expect(svc.verify(jwt, { maxSkew: 0 })).rejects.toThrow()
    })
  })

  it('accepts JWT within clock skew tolerance', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: 'test' }, { expiresIn: '5s' })

      const out = await svc.verify(jwt, { maxSkew: 120 })
      expect(out.payload.data).toBe('test')
    })
  })

  it('requires exp claim by default', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: 'test' })

      const out = await svc.verify(jwt)
      expect(out.payload.exp).toBeDefined()
    })
  })

  it('allows disabling exp requirement with requireExp: false', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: 'test' })

      const out = await svc.verify(jwt, { requireExp: false, requiredClaims: [] })
      expect(out.payload.data).toBe('test')
    })
  })

  it('validates custom required claims', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ userId: '123', role: 'admin' })

      const out = await svc.verify(jwt, { requiredClaims: ['userId', 'role'] })
      expect(out.payload.userId).toBe('123')
      expect(out.payload.role).toBe('admin')
    })
  })

  it('throws when required claim is missing', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ userId: '123' })

      await expect(
        svc.verify(jwt, { requiredClaims: ['userId', 'role'] }),
      ).rejects.toThrow()
    })
  })
})

describe('JsonWebTokenService issuer/audience validation', () => {
  it('rejects token with wrong issuer', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: 'test' }, { issuer: 'issuer-a' })

      await expect(svc.verify(jwt, { issuer: 'issuer-b' })).rejects.toThrow()
    })
  })

  it('rejects token with wrong audience', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: 'test' }, { audience: 'app-a' })

      await expect(svc.verify(jwt, { audience: 'app-b' })).rejects.toThrow()
    })
  })

  it('accepts token with matching issuer from array', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: 'test' }, { issuer: 'issuer-b' })

      const out = await svc.verify(jwt, { issuer: ['issuer-a', 'issuer-b'] })
      expect(out.payload.data).toBe('test')
    })
  })

  it('accepts token when audience is in audience array', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: 'test' }, { audience: ['app-a', 'app-b'] })

      const out = await svc.verify(jwt, { audience: 'app-a' })
      expect(out.payload.data).toBe('test')
    })
  })
})

describe('JsonWebTokenService remote JWKS edge cases', () => {
  it('throws when requireRemoteJwks is true and all JWKS fail', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const svc = new JsonWebTokenService(ks)
      const jwt = await svc.sign({ data: 'test' })

      const jose = await import('jose')
      const spy = jest.spyOn(jose, 'createRemoteJWKSet').mockImplementation(
        () =>
          (async () => {
            throw new Error('network failed')
          }) as unknown as ReturnType<typeof jest.spyOn>,
      ) as unknown as ReturnType<typeof jest.spyOn>

      await expect(
        svc.verify(jwt, {
          jwksUrls: ['https://bad.example/jwks'],
          requireRemoteJwks: true,
        }),
      ).rejects.toThrow('Remote JWKS verification required but all attempts failed')

      spy.mockRestore()
    })
  })

  it('throws when requireRemoteJwks is true and all issuerJwks URLs fail', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const mockLogger = {
        warn: jest.fn(),
      }
      const svc = new JsonWebTokenService(ks, mockLogger as unknown as Logger)
      const jwt = await svc.sign({ data: 'test' }, { issuer: 'issuer-a' })

      const jose = await import('jose')
      const spy = jest.spyOn(jose, 'createRemoteJWKSet').mockImplementation(
        () =>
          (async () => {
            throw new Error('network failed')
          }) as unknown as ReturnType<typeof jest.spyOn>,
      ) as unknown as ReturnType<typeof jest.spyOn>

      await expect(
        svc.verify(jwt, {
          issuerJwks: [
            { issuer: 'issuer-a', jwksUrl: 'https://bad1.example/jwks' },
            { issuer: 'issuer-b', jwksUrl: 'https://bad2.example/jwks' },
          ],
          requireRemoteJwks: true,
        }),
      ).rejects.toThrow('Remote JWKS verification required but all attempts failed')

      // Verify warnings were logged for each failed attempt
      expect(mockLogger.warn).toHaveBeenCalledTimes(2)

      spy.mockRestore()
    })
  })

  it('logs warnings when JWKS URLs fail but continues to next', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const kid = 'K1'
    const env = {
      CRYPTO_ACTIVE_KID: kid,
      CRYPTO_ALLOWED_KIDS_AES: '',
      CRYPTO_ALLOWED_KIDS_SIGN: '',
      [`CRYPTO_ED25519_PRIV_PEM_${kid}`]: privateKey
        .export({ format: 'pem', type: 'pkcs8' })
        .toString(),
      [`CRYPTO_ED25519_PUB_PEM_${kid}`]: publicKey
        .export({ format: 'pem', type: 'spki' })
        .toString(),
    }

    await withEnv(env, async () => {
      const ks = new EnvKeyStore()
      const mockLogger = {
        warn: jest.fn(),
      }
      const svc = new JsonWebTokenService(ks, mockLogger as unknown as Logger)
      const jwt = await svc.sign({ data: 'test' })

      const jose = await import('jose')
      const spy = jest.spyOn(jose, 'createRemoteJWKSet').mockImplementation(
        () =>
          (async () => {
            throw new Error('network')
          }) as unknown as ReturnType<typeof jest.spyOn>,
      ) as unknown as ReturnType<typeof jest.spyOn>

      const out = await svc.verify(jwt, {
        jwksUrls: ['https://bad.example/jwks'],
      })
      expect(out.payload.data).toBe('test')
      expect(mockLogger.warn).toHaveBeenCalled()

      spy.mockRestore()
    })
  })
})
