/**
 * Stores for counters and token bindings.
 *
 * A store is two methods, so anything can back it:
 *
 *   incr(key, ttlMs, now)          -> Promise<number>       count after adding one; the key expires after ttlMs
 *   claim(key, value, ttlMs, now)  -> Promise<string|null>  set if absent and return null, else return the value already there
 *
 * Keys are already hashed and namespaced by the guard; a store never sees a
 * raw fingerprint or address.
 */

/**
 * Per-process memory. The honest default for one process: not shared between
 * instances, empty after a restart. Bounded, so a spray of keys cannot grow it
 * without limit.
 */
export function createMemoryStore({ maxKeys = 100_000 } = {}) {
  const map = new Map()
  const sweep = (now) => {
    if (map.size <= maxKeys) return
    for (const [k, entry] of map) {
      if (entry.exp <= now || map.size > maxKeys) map.delete(k)
      if (map.size <= maxKeys * 0.9) break
    }
  }
  const live = (key, now) => {
    const entry = map.get(key)
    if (entry && entry.exp <= now) {
      map.delete(key)
      return undefined
    }
    return entry
  }
  return {
    async incr(key, ttlMs, now = Date.now()) {
      const entry = live(key, now)
      if (entry) {
        entry.n += 1
        return entry.n
      }
      map.set(key, { n: 1, exp: now + ttlMs })
      sweep(now)
      return 1
    },
    async claim(key, value, ttlMs, now = Date.now()) {
      const entry = live(key, now)
      if (entry) return entry.v
      map.set(key, { v: value, exp: now + ttlMs })
      sweep(now)
      return null
    },
    get size() {
      return map.size
    },
  }
}

/**
 * SQLite, for limits that survive a restart. Takes an open database from
 * bun:sqlite, node:sqlite (DatabaseSync) or better-sqlite3: anything with
 * `exec(sql)` and `prepare(sql).get(...)` / `.run(...)`. Creates one table.
 */
export function createSqliteStore(db, { table = 'browser_fingerprint_counters' } = {}) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) throw new TypeError('browser-fingerprint: bad table name')
  db.exec(`CREATE TABLE IF NOT EXISTS ${table} (k TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0, v TEXT, exp INTEGER NOT NULL)`)
  const read = db.prepare(`SELECT n, v, exp FROM ${table} WHERE k = ?`)
  const put = db.prepare(`INSERT OR REPLACE INTO ${table} (k, n, v, exp) VALUES (?, ?, ?, ?)`)
  const bump = db.prepare(`UPDATE ${table} SET n = n + 1 WHERE k = ?`)
  const purge = db.prepare(`DELETE FROM ${table} WHERE exp <= ?`)
  let writes = 0
  const maybePurge = (now) => {
    if (++writes % 500 === 0) purge.run(now)
  }
  return {
    async incr(key, ttlMs, now = Date.now()) {
      const row = read.get(key)
      maybePurge(now)
      if (row && Number(row.exp) > now) {
        bump.run(key)
        return Number(row.n) + 1
      }
      put.run(key, 1, null, now + ttlMs)
      return 1
    },
    async claim(key, value, ttlMs, now = Date.now()) {
      const row = read.get(key)
      if (row && Number(row.exp) > now) return row.v
      put.run(key, 0, value, now + ttlMs)
      maybePurge(now)
      return null
    },
  }
}

/**
 * Redis, for limits shared by several instances. Pass a function that sends
 * one command as an array of strings and resolves with the reply:
 *
 *   ioredis:     createRedisStore((args) => redis.call(...args))
 *   node-redis:  createRedisStore((args) => client.sendCommand(args))
 *   Bun:         createRedisStore((args) => redis.send(args[0], args.slice(1)))
 */
export function createRedisStore(send, { prefix = 'bfp:' } = {}) {
  if (typeof send !== 'function') throw new TypeError('browser-fingerprint: createRedisStore needs a send(args) function')
  return {
    async incr(key, ttlMs) {
      const n = Number(await send(['INCR', prefix + key]))
      if (n === 1) await send(['PEXPIRE', prefix + key, String(ttlMs)])
      return n
    },
    async claim(key, value, ttlMs) {
      const set = await send(['SET', prefix + key, value, 'PX', String(ttlMs), 'NX'])
      if (set === 'OK' || set === true) return null
      const existing = await send(['GET', prefix + key])
      return existing === null || existing === undefined ? null : String(existing)
    },
  }
}
