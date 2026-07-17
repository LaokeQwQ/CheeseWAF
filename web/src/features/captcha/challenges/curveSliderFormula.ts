import { clampCoordinate } from '../interaction';

export const CURVE_SLIDER_MAX_OFFSET_PERCENT = 16;

/** Maps a 0–10000 slider value to a relative horizontal movement. */
export function curveSliderOffsetPercent(value: number): number {
  const next = clampCoordinate(Math.round(value));
  return ((next - 5_000) / 5_000) * CURVE_SLIDER_MAX_OFFSET_PERCENT;
}
