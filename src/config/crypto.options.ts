import type { ModuleMetadata } from '@nestjs/common'

export interface CryptoModuleOptions {
  enableSymmetric?: boolean
  enableHmac?: boolean
  enableSigning?: boolean
  enablePassword?: boolean
  enableRandom?: boolean
  bcryptCost?: number
  passwordAlgorithm?: 'bcrypt' | 'argon2'
  argon2?: {
    timeCost?: number
    memoryCost?: number
    parallelism?: number
    version?: import('@node-rs/argon2').Version
  }
  keystore?: {
    type?: 'env' | 'file'
    env?: import('../keystore/key-store').EnvKeyStoreOptions
    file?: import('../keystore/file-key-store').FileKeyStoreOptions
  }
  /** Maximum input size in bytes for encryption operations (default: 10MB) */
  maxEncryptionInputSize?: number
  /** Maximum input size in bytes for signing operations (default: 10MB) */
  maxSigningInputSize?: number
  /** Maximum input size in bytes for HMAC operations (default: 10MB) */
  maxHmacInputSize?: number
}

export type CryptoModuleAsyncOptions = Pick<ModuleMetadata, 'imports'> & {
  useFactory: (...args: unknown[]) => Promise<CryptoModuleOptions> | CryptoModuleOptions
  inject?: ReadonlyArray<
    | import('@nestjs/common').InjectionToken
    | import('@nestjs/common').OptionalFactoryDependency
  >
}

export const defaultCryptoOptions: Required<CryptoModuleOptions> = {
  enableSymmetric: true,
  enableHmac: true,
  enableSigning: true,
  enablePassword: true,
  enableRandom: true,
  bcryptCost: 12,
  passwordAlgorithm: 'bcrypt',
  argon2: { timeCost: 3, memoryCost: 64 * 1024, parallelism: 1, version: 1 },
  keystore: { type: 'env', env: {} },
  maxEncryptionInputSize: 10 * 1024 * 1024,
  maxSigningInputSize: 10 * 1024 * 1024,
  maxHmacInputSize: 10 * 1024 * 1024,
}
