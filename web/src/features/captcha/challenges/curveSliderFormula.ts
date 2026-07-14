import { clampCoordinate } from '../interaction';
import type { CaptchaPoint } from '../protocol';

export const CURVE_SLIDER_SAMPLE_COUNT = 33;

const COORDINATE_MAX = 10_000;
const CENTER = 5_000;
const START_X = 900;
const WIDTH = 8_200;
const AMPLITUDE_MIN = 650;
const AMPLITUDE_SPAN = 1_900;

/** Public rendering contract mirrored by internal/captcha/visual_curve.go. */
export function curveSliderPoints(parameter: number, version: number): CaptchaPoint[] {
  const normalizedParameter = clampCoordinate(Math.round(parameter));
  const amplitude = AMPLITUDE_MIN + Math.trunc((normalizedParameter * AMPLITUDE_SPAN) / COORDINATE_MAX);
  const phase = (normalizedParameter / COORDINATE_MAX) * Math.PI;

  return Array.from({ length: CURVE_SLIDER_SAMPLE_COUNT }, (_, index) => {
    const t = index / (CURVE_SLIDER_SAMPLE_COUNT - 1);
    return {
      x: START_X + Math.round(t * WIDTH),
      y: clampCoordinate(CENTER + Math.round(curveSliderWave(t, phase, version) * amplitude)),
    };
  });
}

function curveSliderWave(t: number, phase: number, version: number): number {
  if (version === 1) return Math.sin(t * Math.PI + phase);
  if (version === 2) return Math.sin(t * 2 * Math.PI + phase) * 0.72;
  return Math.sin(t * Math.PI + phase) * 0.62 + Math.sin(t * 3 * Math.PI - phase) * 0.24;
}
