import { Buffer } from 'node:buffer'
import { Readable } from 'node:stream'

import { Test } from '@nestjs/testing'

import { CryptoModule, KEY_STORE } from '../../src/module/crypto.module'
import { CryptoStreamService } from '../../src/services/crypto-stream.service'
import { TestKeystoreBuilder } from '../utils/keystore-builders'

import type { INestApplication } from '@nestjs/common'

jest.setTimeout(45_000)

describe('Streaming operations (e2e)', () => {
  let app: INestApplication
  let cryptoStream: CryptoStreamService

  beforeAll(async () => {
    const keystore = new TestKeystoreBuilder()
      .withActiveKid('K1')
      .withAesKey('K1')
      .withHmacKey('K1')
      .build()

    const module = await Test.createTestingModule({
      imports: [CryptoModule.register()],
    })
      .overrideProvider(KEY_STORE)
      .useValue(keystore)
      .compile()

    app = module.createNestApplication()
    await app.init()

    cryptoStream = app.get(CryptoStreamService)
  })

  afterAll(async () => {
    await app?.close()
  })

  it('encrypts and decrypts large data using streams', async () => {
    const largeData = Buffer.alloc(1024 * 1024, 0xab) // 1MB

    // Encrypt
    const { meta, cipher } = cryptoStream.createEncryptStream({ aad: 'large-file' })

    const encrypted: Buffer[] = []
    encrypted.push(cipher.update(largeData), cipher.final())

    const { tag } = cryptoStream.finalizeEncryptStream(meta, cipher)
    const ciphertext = Buffer.concat(encrypted)

    // Decrypt
    const decipher = cryptoStream.createDecryptStream({ ...meta, tag })

    const decrypted: Buffer[] = []
    decrypted.push(decipher.update(ciphertext), decipher.final())

    const plaintext = Buffer.concat(decrypted)
    expect(plaintext).toEqual(largeData)
  })

  it('HMAC of large data using stream', async () => {
    const largeData = Buffer.alloc(128 * 1024, 0xcd) // 128KB

    // Compute HMAC using stream
    const { transform, finalize } = cryptoStream.hmacStream()
    transform.resume()

    // Pipe data through
    transform.write(largeData)
    transform.end()

    await new Promise<void>(resolve => {
      transform.on('finish', resolve)
    })

    const { mac } = finalize()
    expect(mac).toBeDefined()
    expect(mac.length).toBeGreaterThan(0)

    // Verify determinism
    const { transform: transform2, finalize: finalize2 } = cryptoStream.hmacStream()
    transform2.resume()
    transform2.write(largeData)
    transform2.end()

    await new Promise<void>(resolve => {
      transform2.on('finish', resolve)
    })

    const { mac: mac2 } = finalize2()
    expect(mac2).toBe(mac)
  })

  it('multiple chunks processed correctly', async () => {
    const chunks = [
      Buffer.from('chunk one '),
      Buffer.from('chunk two '),
      Buffer.from('chunk three'),
    ]
    const expected = Buffer.concat(chunks)

    // Encrypt in chunks
    const { meta, cipher } = cryptoStream.createEncryptStream()

    const encrypted: Buffer[] = []
    for (const chunk of chunks) {
      encrypted.push(cipher.update(chunk))
    }
    encrypted.push(cipher.final())

    const { tag } = cryptoStream.finalizeEncryptStream(meta, cipher)
    const ciphertext = Buffer.concat(encrypted)

    // Decrypt
    const decipher = cryptoStream.createDecryptStream({ ...meta, tag })

    const decrypted: Buffer[] = []
    decrypted.push(decipher.update(ciphertext), decipher.final())

    const plaintext = Buffer.concat(decrypted)
    expect(plaintext).toEqual(expected)
  })

  it('stream errors are handled properly', async () => {
    const { meta, cipher } = cryptoStream.createEncryptStream({ aad: 'test' })

    const plaintext = Buffer.from('test data')
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const { tag } = cryptoStream.finalizeEncryptStream(meta, cipher)

    // Create decipher with wrong AAD
    const badMeta = { ...meta, aad: undefined }
    const decipher = cryptoStream.createDecryptStream({ ...badMeta, tag })

    expect(() => {
      decipher.update(ciphertext)
      decipher.final()
    }).toThrow()
  })

  it('encrypts and decrypts via Node.js streams', async () => {
    const testData = Buffer.from('streaming test data'.repeat(100))

    // Create input stream
    const inputStream = Readable.from([testData])

    // Encrypt
    const { meta, cipher } = cryptoStream.createEncryptStream()

    const encryptedChunks: Buffer[] = []
    inputStream.pipe(cipher)

    cipher.on('data', (chunk: Buffer) => {
      encryptedChunks.push(chunk)
    })

    await new Promise<void>((resolve, reject) => {
      cipher.on('end', resolve)
      cipher.on('error', reject)
    })

    const { tag } = cryptoStream.finalizeEncryptStream(meta, cipher)
    const ciphertext = Buffer.concat(encryptedChunks)

    // Decrypt
    const ciphertextStream = Readable.from([ciphertext])
    const decipher = cryptoStream.createDecryptStream({ ...meta, tag })

    const decryptedChunks: Buffer[] = []
    ciphertextStream.pipe(decipher)

    decipher.on('data', (chunk: Buffer) => {
      decryptedChunks.push(chunk)
    })

    await new Promise<void>((resolve, reject) => {
      decipher.on('end', resolve)
      decipher.on('error', reject)
    })

    const plaintext = Buffer.concat(decryptedChunks)
    expect(plaintext).toEqual(testData)
  })

  it('HMAC stream passes data through unchanged', async () => {
    const testData = Buffer.from('data to hash and pass through')

    const { transform, finalize } = cryptoStream.hmacStream()

    const outputChunks: Buffer[] = []

    transform.on('data', (chunk: Buffer) => {
      outputChunks.push(chunk)
    })

    transform.write(testData)
    transform.end()

    await new Promise<void>(resolve => {
      transform.on('finish', resolve)
    })

    const { mac, kid } = finalize()
    const output = Buffer.concat(outputChunks)

    // Data should pass through unchanged
    expect(output).toEqual(testData)

    // MAC should be computed
    expect(mac).toBeDefined()
    expect(kid).toBe('K1')
  })
})
