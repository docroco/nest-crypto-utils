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

  it('honours explicit bcrypt cost override', async () => {
    const svc = new PasswordService(12)
    const hash = await svc.hash('secret', { bcryptCost: 5 })
    const ok = await svc.verify('secret', hash)
    expect(ok).toBe(true)
  })

  it('passes custom argon2 parameters when provided', async () => {
    const svc = new PasswordService(12)
    const hash = await svc.hash('secret', {
      algorithm: 'argon2',
      argon2: { timeCost: 1, memoryCost: 16 * 1024, parallelism: 2 },
    })
    const ok = await svc.verify('secret', hash)
    expect(ok).toBe(true)
  })

  it('honours numeric bcrypt cost argument', async () => {
    const svc = new PasswordService(4)
    const hash = await svc.hash('secret', 6)
    const ok = await svc.verify('secret', hash)
    expect(ok).toBe(true)
  })
})
