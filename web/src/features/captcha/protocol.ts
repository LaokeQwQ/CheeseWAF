export const RESOLVED_CAPTCHA_TYPES = [
  "pow",
  "curve_draw",
  "curve_slider",
  "shape_slider",
  "rotate",
  "restore_slider",
  "angle",
  "scratch",
  "text_click",
  "icon_click",
] as const;
export const CAPTCHA_TYPES = [
  "random",
  "pow",
  "curve_draw",
  "curve_slider",
  "shape_slider",
  "slider_v2",
  "rotate",
  "restore_slider",
  "angle",
  "scratch",
  "text_click",
  "icon_click",
] as const;
export type CaptchaType = (typeof CAPTCHA_TYPES)[number];
export type ResolvedCaptchaType = (typeof RESOLVED_CAPTCHA_TYPES)[number];
export interface CaptchaPoint {
  x: number;
  y: number;
}
export interface CaptchaTrackPoint extends CaptchaPoint {
  t: number;
  type?: string;
}
export interface CaptchaPresentation {
  kind: string;
  image?: string;
  piece?: string;
  prompt?: string;
  version?: number;
  intensity?: number;
  track?: Record<string, number>;
  width?: number;
  height?: number;
  piece_size?: number;
  piece_y?: number;
  /** Degrees from horizontal for shape_slider piece motion; |angle| < 45. */
  track_angle?: number;
  initial_angle?: number;
  moving_part?: "top" | "bottom";
  max_offset?: number;
  initial_offset?: number;
  shape?: string;
  pow_algorithm?: string;
  pow_difficulty?: number;
  pow_salt?: string;
}
export interface CaptchaChallenge {
  type: ResolvedCaptchaType;
  token: string;
  expires_at: string;
  presentation: CaptchaPresentation;
}
export interface CaptchaResponse {
  token: string;
  point?: CaptchaPoint;
  points?: CaptchaPoint[];
  angle?: number;
  offset?: number;
  track?: CaptchaTrackPoint[];
  duration_ms?: number;
  proof?: string;
}
export interface CaptchaVerifyResult {
  valid: boolean;
  type?: ResolvedCaptchaType;
  reason?: string;
}
export type IssueCaptcha = (
  type: CaptchaType,
  signal?: AbortSignal,
) => Promise<CaptchaChallenge>;
export type VerifyCaptcha = (
  response: CaptchaResponse,
  signal?: AbortSignal,
) => Promise<CaptchaVerifyResult>;
const DATA_IMAGE =
  /^data:image\/(?:png|jpe?g|gif|webp|avif);base64,[a-z0-9+/]+=*$/i;
export function safeImageDataUri(value?: string): string | undefined {
  return value && DATA_IMAGE.test(value.trim()) ? value.trim() : undefined;
}
