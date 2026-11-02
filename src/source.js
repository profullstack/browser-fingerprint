/**
 * The browser module's source, for serving it from your own origin (so a
 * `script-src 'self'` policy allows it). Node and Bun only (reads the file).
 *
 *   app.get('/fp.js', (c) => c.body(clientSource(), 200, CLIENT_HEADERS))
 */
import { readFileSync } from 'node:fs'

let source = null

export function clientSource() {
  if (source === null) source = readFileSync(new URL('./client.js', import.meta.url), 'utf8')
  return source
}

export const CLIENT_HEADERS = Object.freeze({
  'content-type': 'text/javascript; charset=utf-8',
  'cache-control': 'public, max-age=3600',
  'x-content-type-options': 'nosniff',
})
