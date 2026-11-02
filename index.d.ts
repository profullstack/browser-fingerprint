import type { Components, Confidence, Payload } from './client.js'
export type { Components, Confidence, Payload } from './client.js'
export { NOISY_KEYS, STABLE_KEYS, stableString, VERSION } from './client.js'

export interface Store {
  incr(key: string, ttlMs: number, now?: number): Promise<number>
  claim(key: string, value: string, ttlMs: number, now?: number): Promise<string | null>
}
export interface Rule { perWindow: number; windowMs: number }
export interface LimitResult { ok: boolean; count: number; retryAfterMs: number; rule: Rule | null }
export interface BotScore { score: number; reasons: string[] }
export type Reason = 'payload_invalid' | 'token_missing' | 'token_malformed' | 'token_bad_signature' | 'token_expired' | 'token_reused' | 'bot'
export interface Verdict {
  ok: boolean
  reason: Reason | null
  /** Keyed hash of the stable components; null only when the payload was malformed. */
  visitorKey: string | null
  /** Keyed hash of the caller's /24 (IPv4) or /64 (IPv6); null without an ip. */
  ipKey: string | null
  confidence: Confidence | null
  bot: BotScore | null
}
export interface GuardOptions {
  secret: string
  store?: Store
  tokenTtlMs?: number
  bindIp?: boolean
  oneVisitorPerToken?: boolean
  botThreshold?: number
}
export interface FingerprintGuard {
  issueChallenge(options?: { ip?: string; binding?: string; now?: number }): Promise<string>
  checkToken(token: unknown, options?: { ip?: string; binding?: string; now?: number }): Promise<{ ok: boolean; reason: Reason | null; nonce?: string; issuedAt?: number }>
  verify(options: { payload: unknown; ip?: string; userAgent?: string; binding?: string; now?: number }): Promise<Verdict>
  limit(key: string, action: string, rules: Rule | Rule[], now?: number): Promise<LimitResult>
  botScore(components: Partial<Components>, options?: { userAgent?: string }): BotScore
  store: Store
}
export declare function createFingerprintGuard(options: GuardOptions): FingerprintGuard
export declare function createLimiter(options?: { store?: Store }): { limit(key: string, action: string, rules: Rule | Rule[], now?: number): Promise<LimitResult>; store: Store }
export declare function botScore(components: Partial<Components>, options?: { userAgent?: string }): BotScore
export declare function ipPrefix(ip: string): string
export declare function keyedHash(secret: string, text: string, length?: number): Promise<string>
export declare function parsePayload(raw: unknown): Payload | null
export declare function validComponents(components: unknown): boolean
export declare function createMemoryStore(options?: { maxKeys?: number }): Store & { readonly size: number }
export declare function createSqliteStore(db: { exec(sql: string): unknown; prepare(sql: string): { get(...args: unknown[]): any; run(...args: unknown[]): unknown } }, options?: { table?: string }): Store
export declare function createRedisStore(send: (args: string[]) => Promise<unknown>, options?: { prefix?: string }): Store
