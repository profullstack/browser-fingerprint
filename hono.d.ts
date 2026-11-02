import type { FingerprintGuard, Rule, Verdict, Payload } from './index.js'
type Ctx = any
export declare function challengeHandler(guard: FingerprintGuard, options?: { getIp?: (c: Ctx) => string; binding?: string }): (c: Ctx) => Promise<Response>
export declare function readPayload(c: Ctx, field?: string): Promise<Payload | null>
export declare function requireVisitor(
  guard: FingerprintGuard,
  options: { action: string; limits?: Rule[]; ipLimits?: Rule[]; getIp?: (c: Ctx) => string; binding?: string; onReject?: (c: Ctx, reason: string, status: number, retryAfterMs: number) => Response | Promise<Response> },
): (c: Ctx, next: () => Promise<void>) => Promise<Response | void>
export type { Verdict }
