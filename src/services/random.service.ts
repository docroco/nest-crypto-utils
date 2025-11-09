/* eslint-disable class-methods-use-this -- this is a service class */
import { Buffer } from 'node:buffer'
import { randomBytes as rb, randomUUID } from 'node:crypto'

import { Injectable } from '@nestjs/common'
import cuid from 'cuid'
import { customAlphabet } from 'nanoid'
import { ulid, isValid as isValidULID } from 'ulid'

import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'
import { base64UrlEncode } from '../utils/encoding'

const nanoidDictionary = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  alphanumeric: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
}

export enum NanoidStringEnum {
  NUMERIC = 'NUMERIC',
  LOWERCASE = 'LOWERCASE',
  UPPERCASE = 'UPPERCASE',
  ALPHABETS = 'ALPHABETS',
  ALPHANUMERIC = 'ALPHANUMERIC',
  LOWERCASE_NUMERIC = 'LOWERCASE_NUMERIC',
  UPPERCASE_NUMERIC = 'UPPERCASE_NUMERIC',
  UUID = 'UUID',
}

/**
 * @summary Configuration for generating random strings with custom character sets.
 */
export interface RandomStringConfig {
  numeric?: boolean
  lowercase?: boolean
  uppercase?: boolean
  hyphenAndUnderscore?: boolean
  space?: boolean
  dot?: boolean
  characters?: string
}

@Injectable()
/**
 * @summary Cryptographically secure random utilities and ID generators.
 * @remarks
 * Provides helpers to generate secrets and various identifiers (UUID, ULID, CUID, nanoid),
 * along with convenience validators for common ID formats.
 */
export class RandomService {
  /**
   * @summary Generate a cryptographically secure random secret string.
   * @param length Number of random bytes to generate (default: 32).
   * @param encoding Output encoding, `base64url` or `hex` (default: `base64url`).
   * @returns Secret as an encoded string.
   * @example
   * ```ts
   * const secret = await random.generateSecret(32, 'base64url')
   * ```
   */
  async generateSecret(
    length = 32,
    encoding: 'base64url' | 'hex' = 'base64url',
  ): Promise<string> {
    const bytes = await this.randomBytes(length)
    if (encoding === 'hex') return Buffer.from(bytes).toString('hex')
    return base64UrlEncode(bytes)
  }

  /**
   * @summary Generate a CUID identifier.
   * @returns A CUID string.
   */
  cuid(): string {
    return cuid()
  }

  /**
   * @summary Generate a ULID identifier.
   * @returns A 26-character ULID string.
   */
  ulid(): string {
    return ulid()
  }

  /**
   * @summary Generate a UUID v4 identifier.
   * @returns A UUID v4 string.
   */
  uuidV4(): string {
    return randomUUID()
  }

  /**
   * @summary Validate if a string is a valid CUID.
   * @param id String to validate.
   * @returns True if valid CUID; otherwise false.
   */
  isCUID(id: string): boolean {
    return cuid.isCuid(id)
  }

  /**
   * @summary Validate if a string is a valid ULID.
   * @param id String to validate.
   * @returns True if valid ULID; otherwise false.
   */
  isULID(id: string): boolean {
    return isValidULID(id)
  }

  /**
   * @summary Validate if a string is a valid UUID v4.
   * @param id String to validate.
   * @returns True if valid UUID v4; otherwise false.
   */
  isUUIDV4(id: string): boolean {
    const v4regex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    return v4regex.test(id)
  }

  /**
   * @summary Generate cryptographically secure random bytes.
   * @param length Number of bytes to generate.
   * @returns Random bytes as a Uint8Array.
   * @example
   * ```ts
   * const bytes = await random.randomBytes(16)
   * ```
   */
  async randomBytes(length: number): Promise<Uint8Array> {
    return new Uint8Array(rb(length))
  }

  /**
   * @summary Generate a random string using a configurable character set.
   * @param typeOrConfig A preset type or a custom configuration object.
   * @param stringLength Length of the generated string (default: 10).
   * @returns Random string composed according to the chosen character set.
   * @example
   * ```ts
   * const s1 = random.randomString(NanoidStringEnum.ALPHANUMERIC, 16)
   * const s2 = random.randomString({ lowercase: true, numeric: true }, 12)
   * ```
   */
  randomString(
    typeOrConfig: RandomStringConfig | NanoidStringEnum = NanoidStringEnum.ALPHANUMERIC,
    stringLength: number = 10,
  ): string {
    if (typeOrConfig === NanoidStringEnum.UUID) return this.uuidV4()

    let config: RandomStringConfig = {}
    if (typeof typeOrConfig == 'object') config = typeOrConfig
    else
      switch (typeOrConfig) {
        case NanoidStringEnum.NUMERIC: {
          config.numeric = true
          break
        }

        case NanoidStringEnum.ALPHABETS: {
          config.uppercase = true
          config.lowercase = true
          break
        }

        case NanoidStringEnum.LOWERCASE: {
          config.lowercase = true
          break
        }

        case NanoidStringEnum.LOWERCASE_NUMERIC: {
          config.lowercase = true
          config.numeric = true
          break
        }

        case NanoidStringEnum.UPPERCASE: {
          config.uppercase = true
          break
        }

        case NanoidStringEnum.UPPERCASE_NUMERIC: {
          config.uppercase = true
          config.numeric = true
          break
        }

        case NanoidStringEnum.ALPHANUMERIC: {
          config.lowercase = true
          config.uppercase = true
          config.numeric = true
          break
        }

        default: {
          break
        }
      }

    let alphabet = ''
    if (config.numeric) alphabet += nanoidDictionary.numbers
    if (config.lowercase) alphabet += nanoidDictionary.lowercase
    if (config.uppercase) alphabet += nanoidDictionary.uppercase
    if (config.hyphenAndUnderscore) alphabet += '-_'
    if (config.space) alphabet += ' '
    if (config.dot) alphabet += '.'
    if (config.characters) alphabet += config.characters

    if (alphabet.length === 0)
      throw new CryptoError(
        CryptoErrorCode.INPUT_VALIDATION_ERROR,
        'Alphabet must not be empty',
      )
    return customAlphabet(alphabet)(stringLength)
  }

  /**
   * @summary Generate a random alphanumeric string.
   * @param length Length of the string (default: 10).
   * @returns Random alphanumeric string.
   */
  randomAlphanumericString(length: number = 10): string {
    return this.randomString(NanoidStringEnum.ALPHANUMERIC, length)
  }

  /**
   * @summary Generate a random alphabetic string.
   * @param length Length of the string (default: 10).
   * @returns Random alphabetic string.
   */
  randomAlphabeticString(length: number = 10): string {
    return this.randomString(NanoidStringEnum.ALPHABETS, length)
  }
  /**
   * @summary Generate a random numeric string.
   * @param length Length of the string (default: 10).
   * @returns Random numeric string.
   */
  randomNumericString(length: number = 10): string {
    return this.randomString(NanoidStringEnum.NUMERIC, length)
  }
}
