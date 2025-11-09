/* eslint-disable unicorn/prefer-module -- convenience */
/* eslint-disable ts/no-require-imports -- convenience */
/* eslint-disable node/prefer-global/buffer -- convenience */
import { toBytes, concatBytes, zeroize } from './bytes'

describe('utils/bytes', () => {
  it('toBytes converts from string/Uint8Array/Buffer', () => {
    const a = toBytes('abc')
    expect(a).toBeInstanceOf(Uint8Array)
    const b = toBytes(new Uint8Array([1, 2, 3]))
    expect(b).toBeInstanceOf(Uint8Array)
    const buf: Buffer = require('node:buffer').Buffer.from([4, 5])
    const c = toBytes(buf)
    expect(c).toBeInstanceOf(Uint8Array)
    expect([...c]).toEqual([4, 5])
  })

  it('concatBytes joins chunks in order', () => {
    const out = concatBytes(
      new Uint8Array([1]),
      new Uint8Array([2, 3]),
      new Uint8Array([4]),
    )
    expect([...out]).toEqual([1, 2, 3, 4])
  })

  it('zeroize overwrites bytes with zeros', () => {
    const x = new Uint8Array([9, 9, 9])
    zeroize(x)
    expect([...x]).toEqual([0, 0, 0])
  })
})
