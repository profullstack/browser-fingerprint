/**
 * @profullstack/browser-fingerprint (server)
 *
 * Turns a browser's fingerprint payload into a stable, salted `visitorKey` you
 * can throttle on, without keeping the fingerprint:
 *
 *  1. `issueChallenge()` mints a short-lived HMAC token. The browser must fetch
 *     (or be rendered with) one before it can send a payload, so a bot cannot
 *     POST made-up identities without at least running a request per token,
 *     and the token can be bound to the caller's network (`bindIp`).
 *  2. `verify()` checks the token, checks the payload is well-formed, scores
 *     how bot-like it looks, and derives `visitorKey` = HMAC(secret, stable
 *     components). The raw components are dropped; only the keyed hash leaves.
 *  3. `limit()` counts actions per key in fixed windows over a pluggable store.
 *
 * WebCrypto only, so it runs on Node, Bun, Deno and edge runtimes.
 */
import { NOISY_KEYS, stableString, VERSION } from './client.js'
import { createMemoryStore } from './stores.js'

const encoder = new TextEncoder()
const keyCache = new Map()

async function hmacKey(secret) {
  if (!secret || typeof secret !== 'string' || secret.length < 16) {
    throw new TypeError('browser-fingerprint: a secret of at least 16 characters is required')
  }
  let key = keyCache.get(secret)
  if (!key) {
    key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    keyCache.set(secret, key)
  }
  return key
}

function base64url(bytes) {
  let binary = ''
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** HMAC-SHA256 of `text` under `secret`, base64url, cut to `length` characters. */
export async function keyedHash(secret, text, length = 43) {
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), encoder.encode(text))
  return base64url(sig).slice(0, length)
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

/**
 * The network an address belongs to, for binding and for the secondary IP
 * limit: the /24 of an IPv4 address and the /64 of an IPv6 one, because a
 * single household or phone moves around inside those.
 */
export function ipPrefix(ip) {
  if (!ip || typeof ip !== 'string') return ''
  const v = ip.trim().replace(/^::ffff:/i, '')
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return v.split('.').slice(0, 3).join('.')
  if (v.includes(':')) {
    const [head] = v.split('::')
    const groups = head.split(':').filter(Boolean)
    // Expand enough of a compressed address to take the first four groups.
    const full = v.includes('::') ? [...groups, ...Array(8).fill('0')].slice(0, 4) : v.split(':').slice(0, 4)
    return full.map((g) => g.toLowerCase().replace(/^0+(?=.)/, '')).join(':')
  }
  return v
}

/** Read the payload from an object, a JSON string or the base64url string `encodePayload` makes. */
export function parsePayload(raw) {
  if (!raw) return null
  if (typeof raw === 'object') return raw
  if (typeof raw !== 'string' || raw.length > 16_384) return null
  const text = raw.trim()
  try {
    if (text.startsWith('{')) return JSON.parse(text)
    const b64 = text.replace(/-/g, '+').replace(/_/g, '/')
    const binary = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4))
    const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0))
    return JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    return null
  }
}

const STRING_MAX = 512
const shapes = {
  canvas: 'string?',
  canvasStable: 'boolean',
  webglVendor: 'string?',
  webglRenderer: 'string?',
  webglParams: 'string?',
  audio: 'string?',
  screen: 'string',
  availScreen: 'string?',
  colorDepth: 'number',
  pixelRatio: 'number?',
  timezone: 'string?',
  timezoneOffset: 'number?',
  languages: 'array',
  platform: 'string?',
  hardwareConcurrency: 'number?',
  deviceMemory: 'number?',
  fonts: 'string?',
  touch: 'string?',
  userAgent: 'string?',
  webdriver: 'boolean?',
  pluginsLength: 'number?',
  hasChromeObject: 'boolean?',
  outer: 'string?',
  brave: 'boolean?',
  uaBrands: 'string?',
  uaMobile: 'boolean?',
  uaPlatform: 'string?',
  uaArch: 'string?',
  uaBitness: 'string?',
  uaModel: 'string?',
}

/** True when `components` has the shape the client produces, and nothing else. */
export function validComponents(components) {
  if (!components || typeof components !== 'object' || Array.isArray(components)) return false
  for (const key of Object.keys(components)) if (!(key in shapes)) return false
  for (const [key, shape] of Object.entries(shapes)) {
    const value = components[key]
    const optional = shape.endsWith('?')
    if (value === undefined || value === null) {
      if (optional) continue
      return false
    }
    const type = shape.replace('?', '')
    if (type === 'array') {
      if (!Array.isArray(value) || value.length > 16 || !value.every((v) => typeof v === 'string' && v.length <= 64)) return false
    } else if (typeof value !== type) return false
    if (type === 'string' && value.length > (key === 'fonts' ? 2048 : STRING_MAX)) return false
    if (type === 'number' && !Number.isFinite(value)) return false
  }
  return true
}

const UA_OS = [
  [/Windows/i, /^win/i],
  [/Macintosh|Mac OS X/i, /^mac/i],
  [/Android/i, /linux|android/i],
  [/iPhone|iPad|iPod/i, /^(iphone|ipad|ipod|mac)/i],
  [/X11|Linux/i, /linux/i],
]

/**
 * How bot-like a client looks, 0 (a person) to 1 (certainly automated), with
 * the reasons. Heuristics only: automation that patches every one of these
 * still passes, which is why the limits and the IP ceiling exist as well.
 */
export function botScore(components, { userAgent = '' } = {}) {
  const reasons = []
  let score = 0
  const add = (points, reason) => {
    score += points
    reasons.push(reason)
  }
  const c = components || {}
  const ua = String(userAgent || c.userAgent || '')
  if (c.webdriver) add(1, 'webdriver')
  if (/HeadlessChrome|PhantomJS|Puppeteer|Playwright|Electron\//i.test(ua) || /Headless/i.test(c.uaBrands || '')) add(1, 'headless-ua')
  if (userAgent && !/^Mozilla\/5\.0 \(/.test(userAgent)) add(0.6, 'non-browser-ua')
  if (userAgent && c.userAgent && c.userAgent !== userAgent) add(0.4, 'ua-mismatch')
  if (!c.languages || c.languages.length === 0) add(0.3, 'no-languages')
  if (/SwiftShader|llvmpipe|softpipe|Mesa OffScreen/i.test(c.webglRenderer || '')) add(0.3, 'software-gl')
  if (!c.canvas && !c.webglRenderer) add(0.3, 'no-canvas-no-webgl')
  if (!c.screen || /^0x|x0$/.test(c.screen)) add(0.3, 'no-screen')
  if (c.outer === '0x0') add(0.2, 'no-window')
  if (!c.hardwareConcurrency) add(0.1, 'no-cpu-count')
  const os = UA_OS.find(([re]) => re.test(ua))
  if (os && c.platform && !os[1].test(c.platform)) add(0.3, 'platform-mismatch')
  const chromium = /Chrome\/\d/.test(ua) && !/Edg\/|OPR\/|SamsungBrowser/i.test(ua)
  if (chromium && !/Android|Mobile/i.test(ua)) {
    if (c.hasChromeObject === false) add(0.25, 'no-window-chrome')
    if (c.pluginsLength === 0) add(0.15, 'no-plugins')
  }
  return { score: Math.min(1, Math.round(score * 100) / 100), reasons }
}

/**
 * Fixed-window limits over a store.
 *
 * `rules` is one `{ perWindow, windowMs }` or a list of them (a minute, an hour
 * and a day, say); every rule must pass. A refused attempt still counts, so a
 * client that keeps hammering keeps its own window full.
 */
export function createLimiter({ store = createMemoryStore() } = {}) {
  return {
    async limit(key, action, rules, now = Date.now()) {
      if (!key) return { ok: false, count: 0, retryAfterMs: 0, rule: null }
      const list = Array.isArray(rules) ? rules : [rules]
      let refused = null
      let count = 0
      for (const rule of list) {
        const windowMs = Math.max(1000, Math.trunc(rule.windowMs))
        const start = Math.floor(now / windowMs) * windowMs
        count = await store.incr(`lim:${action}:${windowMs}:${start}:${key}`, windowMs, now)
        if (count > rule.perWindow && !refused) refused = { ok: false, count, retryAfterMs: start + windowMs - now, rule }
      }
      return refused ?? { ok: true, count, retryAfterMs: 0, rule: null }
    },
    store,
  }
}

/**
 * The guard: challenges, verification and limits under one secret.
 *
 * Options:
 * - `secret` (required, 16+ chars): keys the tokens and every hash. Rotating
 *   it rotates every visitorKey, which resets all limits and vote identities.
 * - `store`: counters and token bindings (memory by default; see ./stores.js).
 * - `tokenTtlMs` (10 minutes): how long a challenge is good for.
 * - `bindIp` (true): a token only verifies from the network (/24 or /64) it
 *   was issued to.
 * - `oneVisitorPerToken` (true): a token, once used, only verifies for the same
 *   visitorKey, so one challenge cannot mint many identities.
 * - `botThreshold` (0.5): verify() fails with `bot` at or above this score.
 */
export function createFingerprintGuard(options = {}) {
  const {
    secret,
    store = createMemoryStore(),
    tokenTtlMs = 10 * 60_000,
    bindIp = true,
    oneVisitorPerToken = true,
    botThreshold = 0.5,
  } = options
  if (!secret || typeof secret !== 'string' || secret.length < 16) {
    throw new TypeError('browser-fingerprint: createFingerprintGuard needs a secret of at least 16 characters')
  }
  const limiter = createLimiter({ store })

  async function issueChallenge({ ip = '', binding = '', now = Date.now() } = {}) {
    const nonce = base64url(crypto.getRandomValues(new Uint8Array(12)))
    const head = `c${VERSION}.${now.toString(36)}.${nonce}`
    const net = bindIp ? ipPrefix(ip) : ''
    return `${head}.${await keyedHash(secret, `${head}|${binding}|${net}`)}`
  }

  async function checkToken(token, { ip = '', binding = '', now = Date.now() } = {}) {
    if (typeof token !== 'string' || !token) return { ok: false, reason: 'token_missing' }
    const parts = token.split('.')
    if (parts.length !== 4 || parts[0] !== `c${VERSION}`) return { ok: false, reason: 'token_malformed' }
    const [v, at36, nonce, sig] = parts
    const net = bindIp ? ipPrefix(ip) : ''
    const expected = await keyedHash(secret, `${v}.${at36}.${nonce}|${binding}|${net}`)
    if (!safeEqual(sig, expected)) return { ok: false, reason: 'token_bad_signature' }
    const issuedAt = Number.parseInt(at36, 36)
    if (!Number.isFinite(issuedAt) || now - issuedAt < -60_000) return { ok: false, reason: 'token_malformed' }
    if (now - issuedAt > tokenTtlMs) return { ok: false, reason: 'token_expired' }
    return { ok: true, reason: null, nonce, issuedAt }
  }

  /**
   * Verify a payload. Returns
   * `{ ok, reason, visitorKey, ipKey, confidence, bot: { score, reasons } }`.
   * `reason` is a stable code (`payload_invalid`, `token_*`, `token_reused`,
   * `bot`); `visitorKey` is set whenever the payload was well-formed, even if
   * it then failed, so you can still count it.
   */
  async function verify({ payload, ip = '', userAgent = '', binding = '', now = Date.now() } = {}) {
    const ipKey = ip ? await keyedHash(secret, `ip|${ipPrefix(ip)}`, 22) : null
    const body = parsePayload(payload)
    if (!body || body.v !== VERSION || !validComponents(body.components)) {
      return { ok: false, reason: 'payload_invalid', visitorKey: null, ipKey, confidence: null, bot: null }
    }
    // The server decides the confidence from the components, not from what the client claims.
    const c = body.components
    const confidence = c.canvas && c.canvasStable === false ? 'low' : c.brave ? 'medium' : 'high'
    const visitorKey = await keyedHash(secret, stableString(c, { confidence }), 22)
    const bot = botScore(c, { userAgent })
    const base = { visitorKey, ipKey, confidence, bot }
    const token = await checkToken(body.token, { ip, binding, now })
    if (!token.ok) return { ok: false, reason: token.reason, ...base }
    if (oneVisitorPerToken) {
      const owner = await store.claim(`tok:${token.nonce}`, visitorKey, tokenTtlMs + 60_000, now)
      if (owner && owner !== visitorKey) return { ok: false, reason: 'token_reused', ...base }
    }
    if (bot.score >= botThreshold) return { ok: false, reason: 'bot', ...base }
    return { ok: true, reason: null, ...base }
  }

  return {
    issueChallenge,
    checkToken,
    verify,
    /** Count `action` against `key`; see createLimiter. */
    limit: (key, action, rules, now) => limiter.limit(key, action, rules, now),
    botScore,
    store,
  }
}

export { NOISY_KEYS, stableString, VERSION }
