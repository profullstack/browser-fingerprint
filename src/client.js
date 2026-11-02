/**
 * @profullstack/browser-fingerprint/client
 *
 * Collects a device fingerprint in the browser and hands it to your server
 * along with a short-lived challenge token the server signed. No dependencies,
 * no eval, no inline script: serve this file from your own origin and load it
 * as a module (`<script type="module">` or `import('/fp.js')`), so it fits a
 * `script-src 'self'` Content-Security-Policy.
 *
 * Nothing here touches the DOM or `window` at import time, so the module can be
 * imported on a server (for tests, or to share `stableString`).
 *
 * The server never trusts the `visitorId` computed here: it recomputes its own
 * keyed hash from the components (see ./server.js). `visitorId` is for the page.
 */

/** Payload format version. Bump when the component set changes shape. */
export const VERSION = 1

/**
 * The components that make up the stable identity. Everything else is
 * collected only to score how bot-like the client looks.
 *
 * Left out on purpose: the user-agent string (it changes on every browser
 * update), devicePixelRatio (it changes with page zoom) and the window size.
 */
export const STABLE_KEYS = [
  'canvas',
  'webglVendor',
  'webglRenderer',
  'webglParams',
  'audio',
  'screen',
  'colorDepth',
  'timezone',
  'languages',
  'platform',
  'hardwareConcurrency',
  'deviceMemory',
  'fonts',
  'touch',
  'uaPlatform',
  'uaArch',
  'uaBitness',
  'uaModel',
]

/** Components a canvas- or audio-randomizing browser poisons; dropped when confidence is low. */
export const NOISY_KEYS = ['canvas', 'audio']

/**
 * The exact string that is hashed into an identity. The server imports this
 * same function, so the two can never drift.
 */
export function stableString(components, { confidence = 'high' } = {}) {
  const skip = confidence === 'low' ? new Set(NOISY_KEYS) : new Set()
  const parts = []
  for (const key of STABLE_KEYS) {
    if (skip.has(key)) continue
    const value = components?.[key]
    parts.push(`${key}=${value === undefined || value === null ? '' : Array.isArray(value) ? value.join(',') : String(value)}`)
  }
  return `bfp${VERSION}|${parts.join('|')}`
}

const encoder = new TextEncoder()

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(text))
  let hex = ''
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, '0')
  return hex
}

/** A cheap 32-bit FNV-1a hash for signals that only need comparing, not keeping. */
function fnv(text) {
  let h = 0x811c9dc5
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return (h >>> 0).toString(16).padStart(8, '0')
}

const safe = (fn, fallback = null) => {
  try {
    const v = fn()
    return v === undefined ? fallback : v
  } catch {
    return fallback
  }
}

function withTimeout(promise, ms, fallback = null) {
  let timer
  return Promise.race([
    Promise.resolve(promise).catch(() => fallback),
    new Promise((resolve) => {
      timer = setTimeout(() => resolve(fallback), ms)
    }),
  ]).finally(() => clearTimeout(timer))
}

function drawCanvas() {
  const canvas = document.createElement('canvas')
  canvas.width = 240
  canvas.height = 60
  const ctx = canvas.getContext('2d')
  if (!ctx) return null
  ctx.textBaseline = 'top'
  ctx.font = '14px Arial'
  ctx.fillStyle = '#f60'
  ctx.fillRect(110, 1, 62, 20)
  ctx.fillStyle = '#069'
  ctx.fillText('Cwm fjordbank glyphs vext quiz, \u{1F918}', 2, 15)
  ctx.fillStyle = 'rgba(102, 204, 0, 0.7)'
  ctx.fillText('Cwm fjordbank glyphs vext quiz, \u{1F918}', 4, 17)
  ctx.globalCompositeOperation = 'multiply'
  ctx.fillStyle = 'rgb(255,0,255)'
  ctx.beginPath()
  ctx.arc(50, 50, 30, 0, Math.PI * 2, true)
  ctx.closePath()
  ctx.fill()
  return fnv(canvas.toDataURL())
}

/** Draw twice: a browser that randomizes canvas reads gives two different answers. */
function canvasSignal() {
  const a = safe(drawCanvas)
  const b = safe(drawCanvas)
  return { value: a, stable: a !== null && a === b }
}

function webglSignal() {
  return safe(() => {
    const canvas = document.createElement('canvas')
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl')
    if (!gl) return null
    const info = gl.getExtension('WEBGL_debug_renderer_info')
    const vendor = info ? gl.getParameter(info.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR)
    const renderer = info ? gl.getParameter(info.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER)
    const params = [
      gl.MAX_TEXTURE_SIZE,
      gl.MAX_RENDERBUFFER_SIZE,
      gl.MAX_VERTEX_ATTRIBS,
      gl.MAX_VERTEX_UNIFORM_VECTORS,
      gl.MAX_FRAGMENT_UNIFORM_VECTORS,
      gl.MAX_VARYING_VECTORS,
      gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS,
      gl.ALIASED_LINE_WIDTH_RANGE,
      gl.ALIASED_POINT_SIZE_RANGE,
      gl.MAX_VIEWPORT_DIMS,
    ].map((p) => {
      const v = gl.getParameter(p)
      return v && typeof v === 'object' && 'length' in v ? Array.from(v).join('x') : String(v)
    })
    const extensions = (gl.getSupportedExtensions() || []).slice().sort().join(',')
    return { vendor: String(vendor || ''), renderer: String(renderer || ''), params: fnv(`${params.join(';')}|${extensions}`) }
  })
}

async function audioSignal() {
  const Ctx = globalThis.OfflineAudioContext || globalThis.webkitOfflineAudioContext
  if (!Ctx) return null
  try {
    const ctx = new Ctx(1, 5000, 44100)
    const osc = ctx.createOscillator()
    osc.type = 'triangle'
    osc.frequency.value = 10000
    const comp = ctx.createDynamicsCompressor()
    comp.threshold.value = -50
    comp.knee.value = 40
    comp.ratio.value = 12
    comp.attack.value = 0
    comp.release.value = 0.25
    osc.connect(comp)
    comp.connect(ctx.destination)
    osc.start(0)
    const buffer = await withTimeout(ctx.startRendering(), 1000)
    if (!buffer) return null
    const data = buffer.getChannelData(0)
    let sum = 0
    for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i])
    return sum.toFixed(6)
  } catch {
    return null
  }
}

const FONTS = [
  'Arial', 'Arial Black', 'Arial Narrow', 'Bahnschrift', 'Calibri', 'Cambria', 'Candara', 'Comic Sans MS', 'Consolas',
  'Constantia', 'Corbel', 'Courier New', 'DejaVu Sans', 'DejaVu Serif', 'Droid Sans', 'Franklin Gothic Medium', 'Futura',
  'Garamond', 'Geneva', 'Georgia', 'Gill Sans', 'Helvetica', 'Helvetica Neue', 'Impact', 'Liberation Mono',
  'Liberation Sans', 'Lucida Console', 'Lucida Grande', 'Menlo', 'Monaco', 'Noto Sans', 'Optima', 'Palatino',
  'Segoe UI', 'SF Pro Text', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Ubuntu', 'Verdana', 'Roboto', 'Cantarell',
]

/** Which of a fixed list of fonts are installed, by text width against the generic fallbacks. */
function fontSignal() {
  return safe(() => {
    const ctx = document.createElement('canvas').getContext('2d')
    if (!ctx) return null
    const sample = 'mmmmmmmmmmlliWWwi0O@#'
    const bases = ['monospace', 'sans-serif', 'serif']
    const width = (font) => {
      ctx.font = `72px ${font}`
      return ctx.measureText(sample).width
    }
    const base = bases.map(width)
    return FONTS.filter((f) => bases.some((b, i) => width(`'${f}', ${b}`) !== base[i])).join(',')
  })
}

async function clientHints() {
  const data = globalThis.navigator?.userAgentData
  if (!data) return {}
  const high = data.getHighEntropyValues
    ? await withTimeout(data.getHighEntropyValues(['platform', 'architecture', 'bitness', 'model']), 500, {})
    : {}
  return {
    uaBrands: (data.brands || []).map((b) => `${b.brand}/${b.version}`).join(','),
    uaMobile: Boolean(data.mobile),
    uaPlatform: String(high?.platform || data.platform || ''),
    uaArch: String(high?.architecture || ''),
    uaBitness: String(high?.bitness || ''),
    uaModel: String(high?.model || ''),
  }
}

/**
 * Collect the components in the browser.
 *
 * Returns `{ components, visitorId, confidence }`. `confidence` is `low` when
 * the canvas reads differently twice in a row (a privacy browser randomizing
 * it); canvas and audio are then left out of the identity so the rest of the
 * device still groups together. `medium` is a browser known to farble (Brave).
 */
export async function collect() {
  const nav = globalThis.navigator || {}
  const scr = globalThis.screen || {}
  const canvas = canvasSignal()
  const gl = webglSignal()
  const [audio, hints] = await Promise.all([audioSignal(), clientHints()])
  const dims = [scr.width | 0, scr.height | 0].sort((a, b) => b - a)
  const components = {
    canvas: canvas.value,
    canvasStable: canvas.stable,
    webglVendor: gl ? gl.vendor : null,
    webglRenderer: gl ? gl.renderer : null,
    webglParams: gl ? gl.params : null,
    audio,
    screen: `${dims[0]}x${dims[1]}`,
    availScreen: `${scr.availWidth | 0}x${scr.availHeight | 0}`,
    colorDepth: scr.colorDepth | 0,
    pixelRatio: Number(globalThis.devicePixelRatio || 0),
    timezone: safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone, ''),
    timezoneOffset: new Date().getTimezoneOffset(),
    languages: Array.from(nav.languages || (nav.language ? [nav.language] : [])).slice(0, 8),
    platform: String(nav.platform || ''),
    hardwareConcurrency: Number(nav.hardwareConcurrency || 0),
    deviceMemory: Number(nav.deviceMemory || 0),
    fonts: fontSignal(),
    touch: `${Number(nav.maxTouchPoints || 0)}:${'ontouchstart' in globalThis ? 1 : 0}`,
    userAgent: String(nav.userAgent || ''),
    webdriver: Boolean(nav.webdriver),
    pluginsLength: safe(() => nav.plugins.length, 0),
    hasChromeObject: typeof globalThis.chrome === 'object' && globalThis.chrome !== null,
    outer: `${globalThis.outerWidth | 0}x${globalThis.outerHeight | 0}`,
    brave: Boolean(nav.brave),
    ...hints,
  }
  const confidence = !canvas.stable && canvas.value !== null ? 'low' : components.brave ? 'medium' : 'high'
  const visitorId = await sha256Hex(stableString(components, { confidence }))
  return { components, visitorId, confidence }
}

let cached = null

/**
 * Collect the fingerprint and attach a challenge token from your server.
 *
 * `challenge` is a token you already have (for example from a
 * `<meta name="fp-challenge">` the page was rendered with); otherwise one is
 * fetched from `challengeUrl` (GET, JSON `{ token }`). Pass `fresh: true` after
 * the server rejected a token as expired or reused: it skips the meta tag and
 * fetches a new one.
 */
export async function getFingerprint({ challenge, challengeUrl = '/api/fp/challenge', fresh = false } = {}) {
  if (!cached) cached = collect()
  const fp = await cached
  let token = challenge
  if (!token && !fresh) token = safe(() => document.querySelector('meta[name="fp-challenge"]').getAttribute('content'))
  if (!token) {
    const res = await fetch(challengeUrl, { credentials: 'same-origin', headers: { accept: 'application/json' } })
    if (!res.ok) throw new Error(`fingerprint challenge failed (${res.status})`)
    token = (await res.json()).token
  }
  return { v: VERSION, token, visitorId: fp.visitorId, confidence: fp.confidence, components: fp.components }
}

/** The payload as one URL-safe string, for a form field or a header. */
export function encodePayload(payload) {
  const bytes = encoder.encode(JSON.stringify(payload))
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Add the fingerprint to every matching form as a hidden field (default name
 * `fp`) just before it is sent. A form still submits without it if collection
 * fails; the server decides what an unfingerprinted request may do.
 */
export function attachToForms({ selector = 'form[method="post" i]', field = 'fp', ...options } = {}) {
  document.addEventListener(
    'submit',
    async (event) => {
      const form = event.target
      if (!(form instanceof HTMLFormElement) || !form.matches(selector)) return
      if (form.dataset.fpDone === '1') {
        delete form.dataset.fpDone
        return
      }
      event.preventDefault()
      try {
        const payload = await withTimeout(getFingerprint(options), 3000)
        if (payload) {
          let input = form.querySelector(`input[name="${field}"]`)
          if (!input) {
            input = document.createElement('input')
            input.type = 'hidden'
            input.name = field
            form.appendChild(input)
          }
          input.value = encodePayload(payload)
        }
      } catch {}
      form.dataset.fpDone = '1'
      // requestSubmit keeps the pressed button and runs validation; it fires submit again, which passes through.
      if (form.requestSubmit) form.requestSubmit(event.submitter || undefined)
      else {
        delete form.dataset.fpDone
        form.submit()
      }
    },
    true,
  )
}
