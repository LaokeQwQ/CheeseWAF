export type GlobeQualityTier = 0 | 1 | 2;

export type GlobePerformanceState = {
  tier: GlobeQualityTier;
  lowFpsWindows: number;
  healthyFpsWindows: number;
};

export type GlobePerformanceUpdate = GlobePerformanceState & {
  pixelRatio: number;
  hideStarField: boolean;
};

const LOW_FPS_THRESHOLD = 45;
const HEALTHY_FPS_THRESHOLD = 56;
const LOW_FPS_WINDOWS_TO_DEGRADE = 2;
const HEALTHY_FPS_WINDOWS_TO_RECOVER = 3;
const QUALITY_PIXEL_RATIO = [1, 0.82, 0.68] as const;

export const initialGlobePerformanceState: GlobePerformanceState = {
  tier: 0,
  lowFpsWindows: 0,
  healthyFpsWindows: 0,
};

/**
 * Advance the adaptive quality state once per sampling window.
 * Hysteresis prevents the renderer from oscillating when FPS hovers around a threshold.
 */
export function updateGlobePerformance(
  state: GlobePerformanceState,
  fps: number,
  basePixelRatio: number,
  minPixelRatio = Math.max(0.75, basePixelRatio * 0.62),
): GlobePerformanceUpdate {
  const normalizedBase = Math.max(0.75, basePixelRatio);
  const safeMinimum = Math.min(normalizedBase, Math.max(0.75, minPixelRatio));
  let tier = state.tier;
  let lowFpsWindows = state.lowFpsWindows;
  let healthyFpsWindows = state.healthyFpsWindows;

  if (fps < LOW_FPS_THRESHOLD) {
    lowFpsWindows += 1;
    healthyFpsWindows = 0;
    if (lowFpsWindows >= LOW_FPS_WINDOWS_TO_DEGRADE && tier < 2) {
      tier = (tier + 1) as GlobeQualityTier;
      lowFpsWindows = 0;
    }
  } else if (fps >= HEALTHY_FPS_THRESHOLD) {
    healthyFpsWindows += 1;
    lowFpsWindows = 0;
    if (healthyFpsWindows >= HEALTHY_FPS_WINDOWS_TO_RECOVER && tier > 0) {
      tier = (tier - 1) as GlobeQualityTier;
      healthyFpsWindows = 0;
    }
  } else {
    lowFpsWindows = 0;
    healthyFpsWindows = 0;
  }

  const pixelRatio = Math.max(safeMinimum, normalizedBase * QUALITY_PIXEL_RATIO[tier]);
  return {
    tier,
    lowFpsWindows,
    healthyFpsWindows,
    pixelRatio,
    hideStarField: tier >= 2,
  };
}
