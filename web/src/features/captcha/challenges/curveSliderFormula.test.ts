import { describe, expect, it } from 'vitest';
import { CURVE_SLIDER_SAMPLE_COUNT, curveSliderPoints } from './curveSliderFormula';

describe('curveSliderPoints', () => {
  it.each([
    [1, 1800, [[900, 5532], [2950, 5968], [5000, 5838], [7050, 5216], [9100, 4468]]],
    [1, 5000, [[900, 6600], [2950, 6131], [5000, 5000], [7050, 3869], [9100, 3400]]],
    [2, 5000, [[900, 6152], [2950, 5000], [5000, 3848], [7050, 5000], [9100, 6152]]],
    [3, 8200, [[900, 5450], [2950, 4586], [5000, 4292], [7050, 3147], [9100, 4550]]],
  ] as const)('matches the server contract for version %i at %i', (version, parameter, expected) => {
    const points = curveSliderPoints(parameter, version);
    expect(points).toHaveLength(CURVE_SLIDER_SAMPLE_COUNT);
    expect([0, 8, 16, 24, 32].map((index) => [points[index].x, points[index].y])).toEqual(expected);
  });

  it('keeps all three versions visually distinct for the same slider value', () => {
    const signatures = [1, 2, 3].map((version) => JSON.stringify(curveSliderPoints(5000, version)));
    expect(new Set(signatures).size).toBe(3);
  });
});
