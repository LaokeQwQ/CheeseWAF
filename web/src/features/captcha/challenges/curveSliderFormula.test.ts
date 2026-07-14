import { describe, expect, it } from 'vitest';
import { CURVE_SLIDER_MAX_OFFSET_PERCENT, curveSliderOffsetPercent } from './curveSliderFormula';

describe('curveSliderOffsetPercent', () => {
  it('keeps the server-rendered initial displacement unchanged at center', () => {
    expect(curveSliderOffsetPercent(5000)).toBe(0);
  });

  it('maps the full slider range to the fixed relative movement contract', () => {
    expect(curveSliderOffsetPercent(0)).toBe(-CURVE_SLIDER_MAX_OFFSET_PERCENT);
    expect(curveSliderOffsetPercent(10000)).toBe(CURVE_SLIDER_MAX_OFFSET_PERCENT);
  });
});
