import { Module } from '@nestjs/common'

import { CryptoModule } from '../../src/module/crypto.module'

/**
 * Minimal NestJS module for E2E testing.
 * Provides a basic app context with CryptoModule registered.
 */
@Module({
  imports: [
    CryptoModule.register({
      enableSymmetric: true,
      enableHmac: true,
      enableSigning: true,
      enablePassword: true,
      enableRandom: true,
    }),
  ],
})
export class TestAppModule {}
