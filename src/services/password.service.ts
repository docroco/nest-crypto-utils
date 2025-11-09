/* eslint-disable class-methods-use-this -- this is a service class */
import { Injectable } from '@nestjs/common'
import { hash as argon2Hash, verify as argon2Verify } from '@node-rs/argon2'
import bcrypt from 'bcrypt'

import type { Version } from '@node-rs/argon2'

/**
 * @summary Password hashing and verification using bcrypt or argon2 (configurable).
 * @param defaultCost Default bcrypt cost factor (rounds) used when none is provided.
 */
@Injectable()
export class PasswordService {
  constructor(
    private readonly defaultCost = 12,
    private readonly defaultAlg: 'bcrypt' | 'argon2' = 'bcrypt',
    private readonly argon2Defaults: {
      timeCost?: number
      memoryCost?: number
      parallelism?: number
      version?: Version
    } = { timeCost: 3, memoryCost: 64 * 1024, parallelism: 1, version: 1 },
  ) {}

  /**
   * @summary Hash a password using bcrypt.
   * @param password Plaintext password.
   * @param costOrAlg Optional bcrypt cost factor; falls back to instance default.
   * @returns Bcrypt hash string.
   * @example
   * ```ts
   * const hash = await password.hash('secret')
   * ```
   */
  async hash(
    password: string,
    costOrAlg?:
      | number
      | {
          algorithm?: 'bcrypt' | 'argon2'
          bcryptCost?: number
          argon2?: {
            timeCost?: number
            memoryCost?: number
            parallelism?: number
            version?: Version
          }
        },
  ): Promise<string> {
    const alg =
      typeof costOrAlg === 'object'
        ? (costOrAlg.algorithm ?? this.defaultAlg)
        : this.defaultAlg
    if (alg === 'argon2') {
      const a =
        typeof costOrAlg === 'object' && costOrAlg.argon2
          ? costOrAlg.argon2
          : this.argon2Defaults
      return argon2Hash(password, {
        timeCost: a.timeCost ?? this.argon2Defaults.timeCost,
        memoryCost: a.memoryCost ?? this.argon2Defaults.memoryCost,
        parallelism: a.parallelism ?? this.argon2Defaults.parallelism,
        version: a.version ?? this.argon2Defaults.version,
      })
    }
    const saltRounds =
      (typeof costOrAlg === 'number'
        ? costOrAlg
        : typeof costOrAlg === 'object'
          ? costOrAlg.bcryptCost
          : undefined) ?? this.defaultCost
    return bcrypt.hash(password, saltRounds)
  }

  /**
   * @summary Verify a password against a bcrypt hash.
   * @param password Plaintext password.
   * @param hash Bcrypt hash string.
   * @returns True when the password matches.
   * @example
   * ```ts
   * const ok = await password.verify('secret', hash)
   * ```
   */
  async verify(password: string, hash: string): Promise<boolean> {
    if (hash.startsWith('$argon2')) {
      return argon2Verify(hash, password)
    }
    return bcrypt.compare(password, hash)
  }
}
