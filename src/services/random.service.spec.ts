import { base64UrlDecode } from '../utils/encoding'

import { NanoidStringEnum, RandomService } from './random.service'

describe('RandomService IDs', () => {
  const svc = new RandomService()

  it('cuid()', () => {
    const id = svc.cuid()
    expect(typeof id).toBe('string')
    expect(id.length).toBeGreaterThan(0)
  })

  it('ulid()', () => {
    const id = svc.ulid()
    expect(id).toHaveLength(26)
    expect(svc.isULID(id)).toBe(true)
  })

  it('uuidV4()', () => {
    const id1 = svc.uuidV4()
    const v4regex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    expect(v4regex.test(id1)).toBe(true)
    expect(svc.isUUIDV4(id1)).toBe(true)
  })

  it('cuid() with validation', () => {
    const id = svc.cuid()
    expect(typeof id).toBe('string')
    expect(svc.isCUID(id)).toBe(true)
  })

  it('randomAlphanumericString()', () => {
    const s = svc.randomAlphanumericString(16)
    expect(s).toHaveLength(16)
    expect(/^[A-Z0-9]+$/i.test(s)).toBe(true)
  })

  it('randomAlphabeticString()', () => {
    const s = svc.randomAlphabeticString(12)
    expect(s).toHaveLength(12)
    expect(/^[A-Z]+$/i.test(s)).toBe(true)
  })

  it('randomNumericString()', () => {
    const s = svc.randomNumericString(8)
    expect(s).toHaveLength(8)
    expect(/^\d+$/.test(s)).toBe(true)
  })

  it('UUID preset returns a valid UUID v4', () => {
    const id = svc.randomString(NanoidStringEnum.UUID)
    const v4regex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    expect(v4regex.test(id)).toBe(true)
    expect(svc.isUUIDV4(id)).toBe(true)
  })

  it('throws on empty alphabet', () => {
    expect(() => svc.randomString({}, 5)).toThrow()
  })

  it('randomString with symbols enabled', () => {
    const s1 = svc.randomString({ hyphenAndUnderscore: true }, 8)
    expect(/[-_]/.test(s1)).toBe(true)
    const s2 = svc.randomString({ space: true }, 8)
    expect(s2.includes(' ')).toBe(true)
    const s3 = svc.randomString({ dot: true }, 8)
    expect(s3.includes('.')).toBe(true)
  })

  it('randomString with custom characters only', () => {
    const s = svc.randomString({ characters: '!?' }, 12)
    expect(s).toHaveLength(12)
    expect(/^[!?]+$/.test(s)).toBe(true)
  })

  it('nanoid enum presets work', () => {
    const s1 = svc.randomString(NanoidStringEnum.ALPHABETS, 6)
    expect(/^[A-Z]{6}$/i.test(s1)).toBe(true)
    const s2 = svc.randomString(NanoidStringEnum.LOWERCASE_NUMERIC, 6)
    expect(/^[a-z0-9]{6}$/.test(s2)).toBe(true)
    const s3 = svc.randomString(NanoidStringEnum.UPPERCASE_NUMERIC, 6)
    expect(/^[A-Z0-9]{6}$/.test(s3)).toBe(true)
  })

  it('generateSecret() base64url returns requested number of bytes', async () => {
    const secret = await svc.generateSecret(32)
    const bytes = base64UrlDecode(secret)
    expect(bytes).toBeInstanceOf(Uint8Array)
    expect(bytes.length).toBe(32)
  })

  it('generateSecret() hex returns requested number of bytes', async () => {
    const secret = await svc.generateSecret(16, 'hex')
    expect(/^[0-9a-f]+$/i.test(secret)).toBe(true)
    expect(secret.length).toBe(32) // 2 hex chars per byte
  })
})
