/**
 * Hono helpers. Framework-light on purpose: they only use `c.req`, `c.json`,
 * `c.set` and `c.env`, so they also read as the recipe for any other framework.
 */
import { parsePayload } from './server.js'

const defaultIp = (c) => c.env?.ip || ''

/**
 * GET handler that hands the browser a challenge token: `app.get('/api/fp/challenge', challengeHandler(guard))`.
 * Throttle this route by IP yourself if it is busy; a token by itself grants nothing.
 */
export function challengeHandler(guard, { getIp = defaultIp, binding = '' } = {}) {
  return async (c) => c.json({ token: await guard.issueChallenge({ ip: getIp(c), binding }) }, 200, { 'cache-control': 'no-store' })
}

/** The payload from the `x-fingerprint` header, or an `fp` field in a JSON or form body. */
export async function readPayload(c, field = 'fp') {
  const header = c.req.header('x-fingerprint')
  if (header) return parsePayload(header)
  const type = c.req.header('content-type') || ''
  try {
    if (/json/i.test(type)) return parsePayload((await c.req.json())?.[field])
    if (/form/i.test(type)) return parsePayload((await c.req.parseBody())?.[field])
  } catch {}
  return null
}

/**
 * Middleware: refuse the request unless it carries a verified fingerprint that
 * is inside its limits. On success `c.get('visitor')` is the verify() result.
 *
 *   app.post('/api/vote', requireVisitor(guard, {
 *     action: 'vote',
 *     limits: [{ perWindow: 10, windowMs: 60_000 }, { perWindow: 200, windowMs: 86_400_000 }],
 *     ipLimits: [{ perWindow: 60, windowMs: 60_000 }],
 *   }), handler)
 */
export function requireVisitor(guard, { action, limits = [], ipLimits = [], getIp = defaultIp, binding = '', onReject } = {}) {
  const reject = onReject || ((c, reason, status, retryAfterMs) => {
    if (retryAfterMs) c.header('retry-after', String(Math.ceil(retryAfterMs / 1000)))
    return c.json({ ok: false, error: reason }, status)
  })
  return async (c, next) => {
    const ip = getIp(c)
    const result = await guard.verify({ payload: await readPayload(c), ip, userAgent: c.req.header('user-agent') || '', binding })
    if (!result.ok) return reject(c, result.reason, result.reason === 'bot' ? 403 : 400, 0)
    if (ipLimits.length && result.ipKey) {
      const byIp = await guard.limit(result.ipKey, `${action}:ip`, ipLimits)
      if (!byIp.ok) return reject(c, 'rate_limited', 429, byIp.retryAfterMs)
    }
    if (limits.length) {
      const byVisitor = await guard.limit(result.visitorKey, action, limits)
      if (!byVisitor.ok) return reject(c, 'rate_limited', 429, byVisitor.retryAfterMs)
    }
    c.set('visitor', result)
    await next()
  }
}
