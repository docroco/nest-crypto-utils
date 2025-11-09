import { hash as argon2Hash } from '@node-rs/argon2'

import { PasswordService } from './password.service'

describe('PasswordService', () => {
  it('hash and verify roundtrip', async () => {
    const svc = new PasswordService(4)
    const hash = await svc.hash('secret')
    const ok = await svc.verify('secret', hash)
    expect(ok).toBe(true)
  })

  it('hash and verify with argon2', async () => {
    const svc = new PasswordService(12, 'argon2', {
      timeCost: 2,
      memoryCost: 32 * 1024,
      parallelism: 1,
      version: 1,
    })
    const hash = await svc.hash('secret')
    const ok = await svc.verify('secret', hash)
    expect(ok).toBe(true)
  })

  it('auto-detect verify for stored argon2 hash', async () => {
    const argonHash = await argon2Hash('secret', {
      timeCost: 2,
      memoryCost: 32 * 1024,
      parallelism: 1,
    })
    const svc = new PasswordService(4)
    const ok = await svc.verify('secret', argonHash)
    expect(ok).toBe(true)
  })
})
