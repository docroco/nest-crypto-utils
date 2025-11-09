import * as pkg from './index'

describe('package barrel exports', () => {
  it('exposes key services and utilities', () => {
    expect(pkg.CryptoService).toBeDefined()
    expect(pkg.JsonWebSignatureService).toBeDefined()
    expect(pkg.JsonWebTokenService).toBeDefined()
    expect(pkg.RandomService).toBeDefined()
    expect(pkg.canonicalStringify).toBeInstanceOf(Function)
    expect(pkg.zeroize).toBeInstanceOf(Function)
    expect(pkg.isEnvelopeV1).toBeInstanceOf(Function)
  })
})
