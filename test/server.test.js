import { test } from 'node:test'
import assert from 'node:assert/strict'
import { DatabaseSync } from 'node:sqlite'
import {
  botScore,
  createFingerprintGuard,
  createLimiter,
  createMemoryStore,
  createRedisStore,
  createSqliteStore,
  ipPrefix,
  parsePayload,
  stableString,
  validComponents,
} from '../index.js'
import { encodePayload } from '../src/client.js'
import { challengeHandler, requireVisitor } from '../src/hono.js'
import { clientSource } from '../src/source.js'

const SECRET = 'test-secret-0123456789abcdef'
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

const person = (over = {}) => ({
  canvas: 'a1b2c3d4',
  canvasStable: true,
  webglVendor: 'Google Inc. (NVIDIA)',
  webglRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
  webglParams: 'deadbeef',
  audio: '124.043473',
  screen: '2560x1440',
  availScreen: '2560x1400',
  colorDepth: 24,
  pixelRatio: 1,
  timezone: 'America/Los_Angeles',
  timezoneOffset: 480,
  languages: ['en-US', 'en'],
  platform: 'Win32',
  hardwareConcurrency: 16,
  deviceMemory: 8,
  fonts: 'Arial,Calibri,Segoe UI',
  touch: '0:0',
  userAgent: UA,
  webdriver: false,
  pluginsLength: 5,
  hasChromeObject: true,
  outer: '1920x1040',
  brave: false,
  ...over,
})

async function payloadFor(guard, components, { ip = '203.0.113.9', token } = {}) {
  return { v: 1, token: token ?? (await guard.issueChallenge({ ip })), visitorId: 'x', confidence: 'high', components }
}

test('a person verifies and gets a stable visitorKey', async () => {
  const guard = createFingerprintGuard({ secret: SECRET })
  const a = await guard.verify({ payload: await payloadFor(guard, person()), ip: '203.0.113.9', userAgent: UA })
  const b = await guard.verify({ payload: await payloadFor(guard, person({ pixelRatio: 1.25, outer: '800x600' })), ip: '203.0.113.77', userAgent: UA })
  assert.equal(a.ok, true, a.reason)
  assert.equal(b.ok, true, b.reason)
  assert.equal(a.visitorKey, b.visitorKey, 'zoom, window size and the same /24 do not change the key')
  assert.equal(a.ipKey, b.ipKey)
  assert.match(a.visitorKey, /^[A-Za-z0-9_-]{22}$/)
})

test('a different device gets a different key; a different secret too', async () => {
  const guard = createFingerprintGuard({ secret: SECRET })
  const other = createFingerprintGuard({ secret: `${SECRET}-other` })
  const a = await guard.verify({ payload: await payloadFor(guard, person()), ip: '203.0.113.9', userAgent: UA })
  const b = await guard.verify({ payload: await payloadFor(guard, person({ webglRenderer: 'Apple M2' })), ip: '203.0.113.9', userAgent: UA })
  const c = await other.verify({ payload: await payloadFor(other, person()), ip: '203.0.113.9', userAgent: UA })
  assert.notEqual(a.visitorKey, b.visitorKey)
  assert.notEqual(a.visitorKey, c.visitorKey)
})

test('the result never carries the raw components', async () => {
  const guard = createFingerprintGuard({ secret: SECRET })
  const r = await guard.verify({ payload: await payloadFor(guard, person()), ip: '203.0.113.9', userAgent: UA })
  const text = JSON.stringify(r)
  assert.ok(!text.includes('NVIDIA') && !text.includes('Los_Angeles') && !text.includes('203.0.113'))
})

test('tokens: missing, forged, expired, other network, reused for another identity', async () => {
  const guard = createFingerprintGuard({ secret: SECRET, tokenTtlMs: 60_000 })
  const ip = '198.51.100.4'
  const verify = (payload, opts = {}) => guard.verify({ payload, ip, userAgent: UA, ...opts })
  assert.equal((await verify({ v: 1, components: person() })).reason, 'token_missing')
  const token = await guard.issueChallenge({ ip })
  const forged = token.slice(0, -2) + (token.endsWith('AA') ? 'BB' : 'AA')
  assert.equal((await verify({ v: 1, token: forged, components: person() })).reason, 'token_bad_signature')
  const old = await guard.issueChallenge({ ip, now: Date.now() - 120_000 })
  assert.equal((await verify({ v: 1, token: old, components: person() })).reason, 'token_expired')
  assert.equal((await verify({ v: 1, token, components: person() }, { ip: '192.0.2.1' })).reason, 'token_bad_signature')
  assert.equal((await verify({ v: 1, token, components: person() })).ok, true)
  assert.equal((await verify({ v: 1, token, components: person() })).ok, true, 'same identity may reuse its token')
  assert.equal((await verify({ v: 1, token, components: person({ screen: '1366x768' }) })).reason, 'token_reused')
})

test('payloads are validated and may arrive encoded', async () => {
  const guard = createFingerprintGuard({ secret: SECRET })
  const good = await payloadFor(guard, person())
  assert.equal((await guard.verify({ payload: encodePayload(good), ip: '203.0.113.9', userAgent: UA })).ok, true)
  assert.equal((await guard.verify({ payload: JSON.stringify(good), ip: '203.0.113.9', userAgent: UA })).ok, true)
  assert.equal((await guard.verify({ payload: 'garbage', ip: '203.0.113.9' })).reason, 'payload_invalid')
  assert.equal(validComponents({ ...person(), extra: 1 }), false)
  assert.equal(validComponents({ ...person(), screen: 5 }), false)
  assert.equal(validComponents({ ...person(), languages: ['x'.repeat(65)] }), false)
  assert.equal(parsePayload('x'.repeat(20_000)), null)
})

test('bots: webdriver, headless, mismatched UA and platform, software GL', async () => {
  const guard = createFingerprintGuard({ secret: SECRET })
  const bot = async (over, ua = UA) => guard.verify({ payload: await payloadFor(guard, person(over)), ip: '203.0.113.9', userAgent: ua })
  assert.equal((await bot({ webdriver: true })).reason, 'bot')
  const headless = UA.replace('Chrome/', 'HeadlessChrome/')
  assert.equal((await bot({ userAgent: headless }, headless)).reason, 'bot')
  assert.equal((await bot({}, 'curl/8.0')).reason, 'bot')
  assert.equal((await bot({ platform: 'Linux x86_64', webglRenderer: 'Google SwiftShader' })).reason, 'bot')
  assert.ok(botScore(person(), { userAgent: UA }).score < 0.2)
  assert.deepEqual(botScore(person({ languages: [] }), { userAgent: UA }).reasons, ['no-languages'])
})

test('a canvas-randomizing browser is low confidence and keeps one identity', async () => {
  const guard = createFingerprintGuard({ secret: SECRET })
  const a = await guard.verify({ payload: await payloadFor(guard, person({ canvas: '11111111', canvasStable: false, audio: '1.1' })), ip: '203.0.113.9', userAgent: UA })
  const b = await guard.verify({ payload: await payloadFor(guard, person({ canvas: '22222222', canvasStable: false, audio: '2.2' })), ip: '203.0.113.9', userAgent: UA })
  assert.equal(a.confidence, 'low')
  assert.equal(a.visitorKey, b.visitorKey)
  assert.ok(!stableString(person(), { confidence: 'low' }).includes('canvas='))
})

test('limits: every rule counts, refusals tell when to retry', async () => {
  const { limit } = createLimiter()
  const rules = [{ perWindow: 3, windowMs: 60_000 }, { perWindow: 5, windowMs: 3_600_000 }]
  const t = 1_700_000_000_000
  const seen = []
  for (let i = 0; i < 4; i++) seen.push((await limit('k', 'vote', rules, t + i)).ok)
  assert.deepEqual(seen, [true, true, true, false])
  const r = await limit('k', 'vote', rules, t + 10)
  assert.equal(r.ok, false)
  assert.ok(r.retryAfterMs > 0 && r.retryAfterMs <= 60_000)
  assert.equal((await limit('other', 'vote', rules, t)).ok, true)
  assert.equal((await limit('k', 'subscribe', rules, t)).ok, true, 'actions are counted apart')
  // The next minute: the minute rule resets, the hour rule (5) catches it after one more.
  assert.equal((await limit('k', 'vote', rules, t + 61_000)).ok, false, 'hour rule: 6th in the hour')
})

test('memory store expires and stays bounded', async () => {
  const store = createMemoryStore({ maxKeys: 50 })
  for (let i = 0; i < 500; i++) await store.incr(`k${i}`, 1000, 0)
  assert.ok(store.size <= 50)
  assert.equal(await store.incr('x', 1000, 0), 1)
  assert.equal(await store.incr('x', 1000, 500), 2)
  assert.equal(await store.incr('x', 1000, 1500), 1)
})

test('sqlite store: counters and claims survive a new store on the same db', async () => {
  const db = new DatabaseSync(':memory:')
  const a = createSqliteStore(db)
  assert.equal(await a.incr('k', 60_000, 0), 1)
  assert.equal(await a.incr('k', 60_000, 1), 2)
  const b = createSqliteStore(db)
  assert.equal(await b.incr('k', 60_000, 2), 3)
  assert.equal(await b.incr('k', 60_000, 70_000), 1, 'expired window starts over')
  assert.equal(await b.claim('t', 'v1', 1000, 0), null)
  assert.equal(await b.claim('t', 'v2', 1000, 10), 'v1')
  assert.equal(await b.claim('t', 'v3', 1000, 2000), null)
  const guard = createFingerprintGuard({ secret: SECRET, store: b })
  assert.equal((await guard.verify({ payload: await payloadFor(guard, person()), ip: '203.0.113.9', userAgent: UA })).ok, true)
})

test('redis store speaks plain commands', async () => {
  const data = new Map()
  const send = async ([cmd, key, ...rest]) => {
    if (cmd === 'INCR') {
      data.set(key, String(Number(data.get(key) ?? 0) + 1))
      return Number(data.get(key))
    }
    if (cmd === 'PEXPIRE') return 1
    if (cmd === 'SET') {
      if (rest.includes('NX') && data.has(key)) return null
      data.set(key, rest[0])
      return 'OK'
    }
    if (cmd === 'GET') return data.get(key) ?? null
  }
  const store = createRedisStore(send)
  assert.equal(await store.incr('a', 1000), 1)
  assert.equal(await store.incr('a', 1000), 2)
  assert.equal(await store.claim('t', 'x', 1000), null)
  assert.equal(await store.claim('t', 'y', 1000), 'x')
  assert.ok(data.has('bfp:a'))
})

test('ipPrefix groups a household', () => {
  assert.equal(ipPrefix('203.0.113.9'), '203.0.113')
  assert.equal(ipPrefix('::ffff:203.0.113.9'), '203.0.113')
  assert.equal(ipPrefix('2001:db8:abcd:12:1::5'), '2001:db8:abcd:12')
  assert.equal(ipPrefix('2001:db8::1'), '2001:db8:0:0')
  assert.equal(ipPrefix(''), '')
})

test('a secret is required', () => {
  assert.throws(() => createFingerprintGuard({}), /secret/)
  assert.throws(() => createFingerprintGuard({ secret: 'short' }), /secret/)
})

test('hono helpers: challenge, then a guarded route with limits', async () => {
  const guard = createFingerprintGuard({ secret: SECRET })
  // A minimal Hono-shaped context, so the test needs no dependency.
  const ctx = (headers = {}, body = null) => {
    const res = { headers: {} }
    return {
      env: { ip: '203.0.113.9' },
      req: { header: (n) => headers[n.toLowerCase()], json: async () => body, parseBody: async () => body },
      json: (obj, status = 200) => ({ obj, status }),
      header: (k, v) => (res.headers[k] = v),
      set(k, v) {
        this[k] = v
      },
      res,
    }
  }
  const { obj } = await challengeHandler(guard)(ctx())
  assert.ok(obj.token)
  const mw = requireVisitor(guard, { action: 'vote', limits: [{ perWindow: 2, windowMs: 60_000 }] })
  const send = async () => {
    const c = ctx({ 'content-type': 'application/json', 'user-agent': UA }, { fp: { v: 1, token: obj.token, components: person() } })
    let passed = false
    const out = await mw(c, async () => {
      passed = true
    })
    return { passed, out, visitor: c.visitor }
  }
  const one = await send()
  assert.equal(one.passed, true)
  assert.ok(one.visitor.visitorKey)
  assert.equal((await send()).passed, true)
  const three = await send()
  assert.equal(three.passed, false)
  assert.equal(three.out.status, 429)
  const noFp = await mw(ctx({ 'content-type': 'application/json' }, {}), async () => {})
  assert.equal(noFp.status, 400)
})

test('the client module imports on a server and matches the server hash input', async () => {
  const client = await import('../src/client.js')
  assert.equal(client.stableString(person()), stableString(person()))
  assert.ok(clientSource().includes('export async function collect'))
  assert.ok(!/\beval\(|new Function\(/.test(clientSource()))
})
