import { describe, expect, it } from 'vitest';
import { initialGlobePerformanceState, updateGlobePerformance } from './globePerformance';

describe('updateGlobePerformance', () => {
  it('degrades only after two consecutive low-FPS windows', () => {
    const first = updateGlobePerformance(initialGlobePerformanceState, 38, 1.5);
    expect(first.tier).toBe(0);
    const second = updateGlobePerformance(first, 38, 1.5);
    expect(second.tier).toBe(1);
    expect(second.pixelRatio).toBeCloseTo(1.23);
    expect(second.hideStarField).toBe(false);
  });

  it('hides the star field only at the most degraded tier', () => {
    const tierOne = updateGlobePerformance(
      updateGlobePerformance(initialGlobePerformanceState, 38, 1.5),
      38,
      1.5,
    );
    const tierTwoFirst = updateGlobePerformance(tierOne, 38, 1.5);
    const tierTwo = updateGlobePerformance(tierTwoFirst, 38, 1.5);
    expect(tierTwo.tier).toBe(2);
    expect(tierTwo.hideStarField).toBe(true);
    expect(tierTwo.pixelRatio).toBeCloseTo(1.02);
  });

  it('recovers one tier after three healthy windows', () => {
    const degraded = updateGlobePerformance(
      updateGlobePerformance(initialGlobePerformanceState, 38, 1.5),
      38,
      1.5,
    );
    const first = updateGlobePerformance(degraded, 60, 1.5);
    const second = updateGlobePerformance(first, 60, 1.5);
    const recovered = updateGlobePerformance(second, 60, 1.5);
    expect(recovered.tier).toBe(0);
    expect(recovered.pixelRatio).toBeCloseTo(1.5);
    expect(recovered.hideStarField).toBe(false);
  });

  it('does not exceed the base ratio or drop below the configured minimum', () => {
    const base = updateGlobePerformance(initialGlobePerformanceState, 38, 1.1, 0.9);
    const degraded = updateGlobePerformance(updateGlobePerformance(base, 38, 1.1, 0.9), 38, 1.1, 0.9);
    expect(degraded.pixelRatio).toBeGreaterThanOrEqual(0.9);
    expect(degraded.pixelRatio).toBeLessThanOrEqual(1.1);
  });
});
