# @profullstack/browser-fingerprint

One vote per browser, not one per IP address.

Anonymous write actions (votes, sign-ups, quote requests, submissions) need a
limit, and an IP address is a bad key for one: a whole office or a phone
carrier shares one, and anyone with a VPN gets a new one per click. This
package keys limits on the browser instead.

- **Client** (`/client`, ~8 KB, no dependencies, no `eval`, no inline script):
  collects canvas, WebGL vendor/renderer/parameters, an audio-context hash,
  screen and colour depth, timezone, languages, platform, CPU count, device
  memory, an installed-fonts probe, touch support and UA client hints. Serve it
  from your own origin so `script-src 'self'` allows it.
- **Server** (Node, Bun, Deno, edge; WebCrypto only): checks a server-signed,
  short-lived challenge token, validates the payload, scores how bot-like it
  looks, and derives a salted `visitorKey`. Fixed-window limits over a
  pluggable store (memory, SQLite, Redis, or two methods of your own).
- **Hono helpers** (`/hono`): a challenge route and a `requireVisitor`
  middleware.

## Privacy

The server never stores the fingerprint. `verify()` reads the components,
computes `visitorKey = HMAC-SHA256(secret, stable components)` and returns only
that keyed hash (plus a keyed hash of the caller's /24 or /64 network, and a bot
score). Nothing the package returns or stores contains a component or an
address, and a key cannot be turned back into either without the secret.
Rotating the secret rotates every key.

Say so on your privacy page. For example (pit.world's wording):

> Anonymous votes are tied to a salted, hashed fingerprint of your device
> (things like your screen size, graphics card and installed fonts, hashed
> together with a secret key). We keep only the hash, and use it only to stop
> one device voting many times. It is not linked to your searches.

## Install

```sh
npm install @profullstack/browser-fingerprint
```

## How it fits together

1. The page gets a challenge token: rendered into
   `<meta name="fp-challenge" content="...">`, or fetched from your challenge
   route (`GET /api/fp/challenge` by default).
2. The browser collects the components and sends
   `{ v, token, visitorId, confidence, components }` as a JSON field `fp`, a
   form field `fp` (base64url, `encodePayload`) or an `x-fingerprint` header.
3. The server calls `verify()`, then `limit()` on the `visitorKey` (and,
   as a secondary ceiling, on the `ipKey`).

A token is good for 10 minutes, only from the network it was issued to
(`bindIp`), and once used only for the identity that used it
(`oneVisitorPerToken`), so one challenge cannot mint many identities. Made-up
fingerprints are still possible for a determined bot that fetches a token per
identity: that is what the IP ceiling and the bot score are for. This raises
the cost of abuse; it is not an identity system.

## Server

```js
import { createFingerprintGuard } from '@profullstack/browser-fingerprint'

const guard = createFingerprintGuard({ secret: process.env.FINGERPRINT_SECRET })

// Hand out a challenge (or render it into the page).
const token = await guard.issueChallenge({ ip })

// On a write:
const v = await guard.verify({ payload: body.fp, ip, userAgent: request.headers.get('user-agent') })
if (!v.ok) return refuse(v.reason) // payload_invalid | token_* | token_reused | bot
const byVisitor = await guard.limit(v.visitorKey, 'vote', [
  { perWindow: 10, windowMs: 60_000 },
  { perWindow: 60, windowMs: 3_600_000 },
  { perWindow: 300, windowMs: 86_400_000 },
])
const byNetwork = await guard.limit(v.ipKey, 'vote:ip', [{ perWindow: 60, windowMs: 60_000 }])
if (!byVisitor.ok || !byNetwork.ok) return tooMany(Math.max(byVisitor.retryAfterMs, byNetwork.retryAfterMs))
// v.visitorKey is your one-vote-per-browser key.
```

`verify()` returns `{ ok, reason, visitorKey, ipKey, confidence, bot: { score, reasons } }`.
`visitorKey` is set even when verification fails (for a well-formed payload),
so you can count failures too.

Options: `secret` (required, 16+ characters), `store`, `tokenTtlMs` (600000),
`bindIp` (true), `oneVisitorPerToken` (true), `botThreshold` (0.5).

Pass the real client address as `ip`. Read it from your own proxy's header
(Railway, nginx `X-Real-IP` you set), never from a header the client can send.

### Bot score

`botScore(components, { userAgent })` adds up: `navigator.webdriver`, a headless
or non-browser user agent, a user agent that differs from the one the page saw,
no languages, a software renderer (SwiftShader, llvmpipe), no canvas and no
WebGL, a zero-size screen or window, no CPU count, a platform that contradicts
the user agent, and desktop Chrome without `window.chrome` or plugins. At 0.5
`verify()` fails with `bot`. Heuristics only; good automation passes them.

### Confidence

The client draws its canvas twice. Browsers that randomize canvas reads
(Firefox `resistFingerprinting`, some extensions) give two answers: the
payload is then `confidence: 'low'` and the canvas and audio signals are left
out of the key, so the rest of the device still groups together. Brave is
`medium`. The server decides confidence from the components, never from the
client's claim.

### Stores

```js
import { createMemoryStore, createSqliteStore, createRedisStore } from '@profullstack/browser-fingerprint'

createMemoryStore()                                  // default; one process, empty after restart
createSqliteStore(db)                                // bun:sqlite, node:sqlite or better-sqlite3
createRedisStore((args) => redis.call(...args))      // ioredis
createRedisStore((args) => client.sendCommand(args)) // node-redis
```

Your own store is two methods: `incr(key, ttlMs, now) -> count` and
`claim(key, value, ttlMs, now) -> existing value or null`.

## Client

```html
<script type="module">
  import { getFingerprint } from '/fp.js'
  const fp = await getFingerprint() // fetches /api/fp/challenge unless the page has <meta name="fp-challenge">
  await fetch('/api/vote', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ item, value: 1, fp }) })
</script>
```

Or let it add an `fp` field to every POST form just before it is sent (the
form still submits without one if collection fails):

```js
import { attachToForms } from '/fp.js'
attachToForms({ selector: 'form[data-fp]' })
```

Exports: `collect()`, `getFingerprint({ challenge?, challengeUrl?, fresh? })`
(pass `fresh: true` after a `token_*` rejection), `encodePayload(payload)`,
`attachToForms({ selector?, field? })`, `stableString()`, `STABLE_KEYS`.

### Serving the client from your origin

```js
import { clientSource, CLIENT_HEADERS } from '@profullstack/browser-fingerprint/source'
app.get('/fp.js', (c) => c.body(clientSource(), 200, CLIENT_HEADERS))
```

## Hono

```js
import { Hono } from 'hono'
import { createFingerprintGuard } from '@profullstack/browser-fingerprint'
import { challengeHandler, requireVisitor } from '@profullstack/browser-fingerprint/hono'
import { clientSource, CLIENT_HEADERS } from '@profullstack/browser-fingerprint/source'

const guard = createFingerprintGuard({ secret: process.env.FINGERPRINT_SECRET })
const app = new Hono()
const getIp = (c) => c.env.ip // however your server passes the trusted address

app.get('/fp.js', (c) => c.body(clientSource(), 200, CLIENT_HEADERS))
app.get('/api/fp/challenge', challengeHandler(guard, { getIp }))
app.post(
  '/api/vote',
  requireVisitor(guard, {
    action: 'vote',
    getIp,
    limits: [{ perWindow: 10, windowMs: 60_000 }, { perWindow: 300, windowMs: 86_400_000 }],
    ipLimits: [{ perWindow: 60, windowMs: 60_000 }],
  }),
  async (c) => {
    const { visitorKey } = c.get('visitor')
    // upsert the vote keyed on (visitorKey, item)
    return c.json({ ok: true })
  },
)
```

## Next.js (App Router)

```ts
// app/api/fp/challenge/route.ts
import { guard, clientIp } from '@/lib/fingerprint'
export async function GET(req: Request) {
  return Response.json({ token: await guard.issueChallenge({ ip: clientIp(req) }) }, { headers: { 'cache-control': 'no-store' } })
}

// app/api/vote/route.ts
export async function POST(req: Request) {
  const body = await req.json()
  const v = await guard.verify({ payload: body.fp, ip: clientIp(req), userAgent: req.headers.get('user-agent') ?? '' })
  if (!v.ok) return Response.json({ error: v.reason }, { status: v.reason === 'bot' ? 403 : 400 })
  const lim = await guard.limit(v.visitorKey!, 'vote', [{ perWindow: 10, windowMs: 60_000 }])
  if (!lim.ok) return Response.json({ error: 'rate_limited' }, { status: 429 })
  // ...
}
```

Serve the client from `public/fp.js` (copy `node_modules/@profullstack/browser-fingerprint/src/client.js` at build time) or a route that returns `clientSource()`.

## Tests

```sh
node --test
```

## License

MIT, Profullstack, Inc.
