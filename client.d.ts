export declare const VERSION: 1
export declare const STABLE_KEYS: readonly string[]
export declare const NOISY_KEYS: readonly string[]
export type Confidence = 'high' | 'medium' | 'low'
export interface Components {
  canvas: string | null
  canvasStable: boolean
  webglVendor: string | null
  webglRenderer: string | null
  webglParams: string | null
  audio: string | null
  screen: string
  availScreen?: string
  colorDepth: number
  pixelRatio?: number
  timezone?: string
  timezoneOffset?: number
  languages: string[]
  platform?: string
  hardwareConcurrency?: number
  deviceMemory?: number
  fonts?: string | null
  touch?: string
  userAgent?: string
  webdriver?: boolean
  pluginsLength?: number
  hasChromeObject?: boolean
  outer?: string
  brave?: boolean
  uaBrands?: string
  uaMobile?: boolean
  uaPlatform?: string
  uaArch?: string
  uaBitness?: string
  uaModel?: string
}
export interface Payload { v: 1; token: string; visitorId: string; confidence: Confidence; components: Components }
export declare function stableString(components: Partial<Components>, options?: { confidence?: Confidence }): string
export declare function collect(): Promise<{ components: Components; visitorId: string; confidence: Confidence }>
export declare function getFingerprint(options?: { challenge?: string; challengeUrl?: string; fresh?: boolean }): Promise<Payload>
export declare function encodePayload(payload: Payload): string
export declare function attachToForms(options?: { selector?: string; field?: string; challenge?: string; challengeUrl?: string }): void
