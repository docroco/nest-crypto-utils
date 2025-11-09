/* eslint-disable unicorn/prefer-module -- convenience */
/* eslint-disable ts/no-require-imports -- convenience */
import { Global, Module } from '@nestjs/common'

import { defaultCryptoOptions } from '../config/crypto.options'
import { CryptoError, CryptoErrorCode } from '../errors/crypto.error'
import { EnvKeyStore } from '../keystore/env-key-store'
import { FileKeyStore } from '../keystore/file-key-store'
import { CryptoStreamService } from '../services/crypto-stream.service'
import { CryptoService } from '../services/crypto.service'
import { JsonWebEncryptionService } from '../services/json-web-encryption.service'
import { JsonWebSignatureService } from '../services/json-web-signature.service'
import { JsonWebTokenService } from '../services/json-web-token.service'
import { PasswordService } from '../services/password.service'
import { SigningService } from '../services/signing.service'

import type {
  CryptoModuleAsyncOptions,
  CryptoModuleOptions,
} from '../config/crypto.options'
import type { DynamicModule, Provider } from '@nestjs/common'

export const KEY_STORE = Symbol('KEY_STORE')
export const CRYPTO_OPTIONS = Symbol('CRYPTO_OPTIONS')

@Global()
@Module({})
export class CryptoModule {
  /**
   * @summary Register the crypto module with synchronous options.
   * @param options Module options controlling features and bcrypt cost.
   * @returns A dynamic module with conditional providers.
   */
  static register(options: CryptoModuleOptions = {}): DynamicModule {
    const resolved = { ...defaultCryptoOptions, ...options }
    const baseProviders: Provider[] = [
      { provide: CRYPTO_OPTIONS, useValue: resolved },
      {
        provide: KEY_STORE,
        useFactory: () => new EnvKeyStore(resolved.keystore?.env ?? {}),
      },
    ]
    const providers: Provider[] = [
      ...baseProviders,
      ...(resolved.enableSymmetric || resolved.enableHmac
        ? ([
            {
              provide: CryptoService,
              useFactory: (
                ks: import('../keystore/key-store').KeyStore,
                opts: CryptoModuleOptions,
              ) => new CryptoService(ks, opts),
              inject: [KEY_STORE, CRYPTO_OPTIONS],
            },
            {
              provide: CryptoStreamService,
              useFactory: (ks: import('../keystore/key-store').KeyStore) =>
                new CryptoStreamService(ks),
              inject: [KEY_STORE],
            },
          ] as Provider[])
        : []),
      ...(resolved.enablePassword
        ? ([
            {
              provide: PasswordService,
              useFactory: () =>
                new PasswordService(
                  resolved.bcryptCost,
                  resolved.passwordAlgorithm ?? 'bcrypt',
                  resolved.argon2,
                ),
            } as Provider,
          ] as Provider[])
        : []),
      ...(resolved.enableSigning
        ? ([
            {
              provide: SigningService,
              useFactory: (
                ks: import('../keystore/key-store').KeyStore,
                opts: CryptoModuleOptions,
              ) => new SigningService(ks, opts),
              inject: [KEY_STORE, CRYPTO_OPTIONS],
            },
            {
              provide: JsonWebSignatureService,
              useFactory: (ks: import('../keystore/key-store').KeyStore) =>
                new JsonWebSignatureService(ks),
              inject: [KEY_STORE],
            },
            {
              provide: JsonWebEncryptionService,
              useFactory: (ks: import('../keystore/key-store').KeyStore) =>
                new JsonWebEncryptionService(ks),
              inject: [KEY_STORE],
            },
            {
              provide: JsonWebTokenService,
              useFactory: (ks: import('../keystore/key-store').KeyStore) =>
                new JsonWebTokenService(ks),
              inject: [KEY_STORE],
            },
          ] as Provider[])
        : []),
      ...(resolved.enableRandom
        ? [require('../services/random.service').RandomService]
        : []),
    ]
    return { module: CryptoModule, providers, exports: providers, controllers: [] }
  }

  /**
   * @summary Register the crypto module with async factory options.
   * @param options Async factory providing {@link CryptoModuleOptions}.
   * @returns A dynamic module with providers wired to injected options.
   */
  static registerAsync(options: CryptoModuleAsyncOptions): DynamicModule {
    const asyncOptionsProvider = {
      provide: CRYPTO_OPTIONS,
      useFactory: options.useFactory,
      inject: [...(options.inject ?? [])],
    }
    const baseProviders: Provider[] = [
      asyncOptionsProvider,
      {
        provide: KEY_STORE,
        useFactory: async (opts: CryptoModuleOptions) => {
          if (opts.keystore?.type === 'file') {
            if (!opts.keystore.file) {
              throw new CryptoError(
                CryptoErrorCode.CONFIG_ERROR,
                'File keystore directory is required',
              )
            }

            const fks = new FileKeyStore(opts.keystore.file)
            await fks.reload()
            return fks
          }
          return new EnvKeyStore(opts.keystore?.env ?? {})
        },
        inject: [CRYPTO_OPTIONS],
      },
    ]
    // All providers are registered, but conditionally instantiate based on resolved options
    const featureProviders: Provider[] = [
      // CryptoService - conditional on enableSymmetric OR enableHmac
      {
        provide: CryptoService,
        useFactory: (
          ks: import('../keystore/key-store').KeyStore,
          opts: CryptoModuleOptions,
        ) => {
          if (opts.enableSymmetric === false && opts.enableHmac === false) {
            throw new CryptoError(
              CryptoErrorCode.CONFIG_ERROR,
              'CryptoService requires enableSymmetric or enableHmac to be true',
            )
          }
          return new CryptoService(ks, opts)
        },
        inject: [KEY_STORE, CRYPTO_OPTIONS],
      },

      // CryptoStreamService - conditional on enableSymmetric OR enableHmac
      {
        provide: CryptoStreamService,
        useFactory: (
          ks: import('../keystore/key-store').KeyStore,
          opts: CryptoModuleOptions,
        ) => {
          if (opts.enableSymmetric === false && opts.enableHmac === false) {
            throw new CryptoError(
              CryptoErrorCode.CONFIG_ERROR,
              'CryptoStreamService requires enableSymmetric or enableHmac to be true',
            )
          }
          return new CryptoStreamService(ks)
        },
        inject: [KEY_STORE, CRYPTO_OPTIONS],
      },

      // PasswordService - conditional on enablePassword
      {
        provide: PasswordService,
        useFactory: (opts: CryptoModuleOptions) => {
          if (opts.enablePassword === false) {
            throw new CryptoError(
              CryptoErrorCode.CONFIG_ERROR,
              'PasswordService requires enablePassword to be true',
            )
          }
          return new PasswordService(
            opts.bcryptCost ?? 12,
            opts.passwordAlgorithm ?? 'bcrypt',
            opts.argon2,
          )
        },
        inject: [CRYPTO_OPTIONS],
      },

      // SigningService - conditional on enableSigning
      {
        provide: SigningService,
        useFactory: (
          ks: import('../keystore/key-store').KeyStore,
          opts: CryptoModuleOptions,
        ) => {
          if (opts.enableSigning === false) {
            throw new CryptoError(
              CryptoErrorCode.CONFIG_ERROR,
              'SigningService requires enableSigning to be true',
            )
          }
          return new SigningService(ks, opts)
        },
        inject: [KEY_STORE, CRYPTO_OPTIONS],
      },

      // JsonWebSignatureService - conditional on enableSigning
      {
        provide: JsonWebSignatureService,
        useFactory: (
          ks: import('../keystore/key-store').KeyStore,
          opts: CryptoModuleOptions,
        ) => {
          if (opts.enableSigning === false) {
            throw new CryptoError(
              CryptoErrorCode.CONFIG_ERROR,
              'JsonWebSignatureService requires enableSigning to be true',
            )
          }
          return new JsonWebSignatureService(ks)
        },
        inject: [KEY_STORE, CRYPTO_OPTIONS],
      },

      // JsonWebEncryptionService - conditional on enableSigning
      {
        provide: JsonWebEncryptionService,
        useFactory: (
          ks: import('../keystore/key-store').KeyStore,
          opts: CryptoModuleOptions,
        ) => {
          if (opts.enableSigning === false) {
            throw new CryptoError(
              CryptoErrorCode.CONFIG_ERROR,
              'JsonWebEncryptionService requires enableSigning to be true',
            )
          }
          return new JsonWebEncryptionService(ks)
        },
        inject: [KEY_STORE, CRYPTO_OPTIONS],
      },

      // JsonWebTokenService - conditional on enableSigning
      {
        provide: JsonWebTokenService,
        useFactory: (
          ks: import('../keystore/key-store').KeyStore,
          opts: CryptoModuleOptions,
        ) => {
          if (opts.enableSigning === false) {
            throw new CryptoError(
              CryptoErrorCode.CONFIG_ERROR,
              'JsonWebTokenService requires enableSigning to be true',
            )
          }
          return new JsonWebTokenService(ks)
        },
        inject: [KEY_STORE, CRYPTO_OPTIONS],
      },

      // RandomService - conditional on enableRandom
      {
        provide: require('../services/random.service').RandomService,
        useFactory: (opts: CryptoModuleOptions) => {
          if (opts.enableRandom === false) {
            throw new CryptoError(
              CryptoErrorCode.CONFIG_ERROR,
              'RandomService requires enableRandom to be true',
            )
          }
          return new (require('../services/random.service').RandomService)()
        },
        inject: [CRYPTO_OPTIONS],
      },
    ]
    const providers: Provider[] = [...baseProviders, ...featureProviders]
    return {
      module: CryptoModule,
      imports: options.imports ?? [],
      providers,
      exports: providers,
      controllers: [],
    }
  }
}
