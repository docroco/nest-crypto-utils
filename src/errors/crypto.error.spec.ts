import { CryptoError, CryptoErrorCode } from './crypto.error'

describe('CryptoError', () => {
  describe('construction', () => {
    it('constructs with code only', () => {
      const error = new CryptoError(CryptoErrorCode.KEY_NOT_FOUND)

      expect(error).toBeInstanceOf(Error)
      expect(error).toBeInstanceOf(CryptoError)
      expect(error.code).toBe(CryptoErrorCode.KEY_NOT_FOUND)
      expect(error.message).toBe('KEY_NOT_FOUND')
      expect(error.details).toBeUndefined()
    })

    it('constructs with code and message', () => {
      const error = new CryptoError(CryptoErrorCode.KEY_NOT_FOUND, 'Custom message')

      expect(error.code).toBe(CryptoErrorCode.KEY_NOT_FOUND)
      expect(error.message).toBe('Custom message')
      expect(error.details).toBeUndefined()
    })

    it('constructs with code, message, and details', () => {
      const details = { kid: 'K1', alg: 'AES-256-GCM' }
      const error = new CryptoError(
        CryptoErrorCode.KEY_NOT_FOUND,
        'Key not found',
        details,
      )

      expect(error.code).toBe(CryptoErrorCode.KEY_NOT_FOUND)
      expect(error.message).toBe('Key not found')
      expect(error.details).toEqual(details)
    })

    it('has correct name property', () => {
      const error = new CryptoError(CryptoErrorCode.KEY_NOT_FOUND)
      expect(error.name).toBe('CryptoError')
    })

    it('includes code in default message when message omitted', () => {
      const error = new CryptoError(CryptoErrorCode.INVALID_KEY_MATERIAL)
      expect(error.message).toBe('INVALID_KEY_MATERIAL')
    })

    it('details object is accessible', () => {
      const details = { foo: 'bar', baz: 123 }
      const error = new CryptoError(CryptoErrorCode.CONFIG_ERROR, 'Test', details)

      expect(error.details).toBeDefined()
      expect(error.details?.foo).toBe('bar')
      expect(error.details?.baz).toBe(123)
    })
  })

  describe('instanceof checks', () => {
    it('instanceof Error returns true', () => {
      const error = new CryptoError(CryptoErrorCode.KEY_NOT_FOUND)
      expect(error instanceof Error).toBe(true)
    })

    it('instanceof CryptoError returns true', () => {
      const error = new CryptoError(CryptoErrorCode.KEY_NOT_FOUND)
      expect(error instanceof CryptoError).toBe(true)
    })
  })

  describe('error propagation', () => {
    it('can be thrown and caught', () => {
      expect(() => {
        throw new CryptoError(CryptoErrorCode.KEY_NOT_FOUND, 'Test error')
      }).toThrow('Test error')
    })

    it('can be caught as Error', () => {
      try {
        throw new CryptoError(CryptoErrorCode.KEY_NOT_FOUND, 'Test')
      } catch (error) {
        expect(error).toBeInstanceOf(Error)
        expect((error as CryptoError).code).toBe(CryptoErrorCode.KEY_NOT_FOUND)
      }
    })

    it('can be caught as CryptoError', () => {
      try {
        throw new CryptoError(CryptoErrorCode.DECRYPT_AUTH_FAILED)
      } catch (error) {
        if (error instanceof CryptoError) {
          expect(error.code).toBe(CryptoErrorCode.DECRYPT_AUTH_FAILED)
        } else {
          fail('Error should be CryptoError')
        }
      }
    })
  })
})

describe('CryptoErrorCode enum', () => {
  it('all expected error codes are defined', () => {
    const expectedCodes = [
      'KEY_NOT_FOUND',
      'INVALID_KEY_MATERIAL',
      'UNSUPPORTED_ALG',
      'INVALID_ENVELOPE',
      'DECRYPT_AUTH_FAILED',
      'SIGN_VERIFY_FAILED',
      'ENCODING_ERROR',
      'CONFIG_ERROR',
      'INPUT_VALIDATION_ERROR',
      'SIZE_LIMIT_EXCEEDED',
    ]

    for (const code of expectedCodes) {
      expect(CryptoErrorCode[code as keyof typeof CryptoErrorCode]).toBe(code)
    }
  })

  it('no duplicate values in enum', () => {
    const values = Object.values(CryptoErrorCode)
    const uniqueValues = new Set(values)
    expect(values.length).toBe(uniqueValues.size)
  })

  it('enum has correct count of codes', () => {
    const codeCount = Object.keys(CryptoErrorCode).length
    expect(codeCount).toBe(11)
  })
})
