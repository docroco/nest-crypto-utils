import { CryptoErrorCode } from '../errors/crypto.error'

import { canonicalStringify } from './canonical'

describe('canonicalStringify', () => {
  it('produces stable ordering', () => {
    const a = { b: 1, a: 2, z: { y: 1, x: 2 } }
    const b = { z: { x: 2, y: 1 }, a: 2, b: 1 }
    const sa = canonicalStringify(a)
    const sb = canonicalStringify(b)
    expect(sa).toBe(sb)
  })

  it('throws on circular object references', () => {
    // eslint-disable-next-line ts/no-explicit-any -- need any to create circular reference for test
    const obj: any = { a: 1 }
    obj.self = obj
    try {
      canonicalStringify(obj)
      fail('Should have thrown')
    } catch (error) {
      expect(error.code).toBe(CryptoErrorCode.INPUT_VALIDATION_ERROR)
      expect(error.message).toContain('Circular reference')
    }
  })

  it('throws on circular array references', () => {
    // eslint-disable-next-line ts/no-explicit-any -- need any to create circular reference for test
    const arr: any = [1, 2]
    arr.push(arr)
    try {
      canonicalStringify(arr)
      fail('Should have thrown')
    } catch (error) {
      expect(error.code).toBe(CryptoErrorCode.INPUT_VALIDATION_ERROR)
      expect(error.message).toContain('Circular reference')
    }
  })

  it('throws on nested circular references', () => {
    // eslint-disable-next-line ts/no-explicit-any -- need any to create circular reference for test
    const obj: any = { a: { b: { c: 1 } } }
    obj.a.b.circular = obj.a
    try {
      canonicalStringify(obj)
      fail('Should have thrown')
    } catch (error) {
      expect(error.code).toBe(CryptoErrorCode.INPUT_VALIDATION_ERROR)
    }
  })
})
