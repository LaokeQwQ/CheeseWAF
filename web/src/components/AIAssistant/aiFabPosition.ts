export type FabPosition = {
  left: number;
  top: number;
};

export const AI_FAB_SIZE = 46;
export const AI_FAB_MARGIN = 12;
/** Matches default CSS anchors (right / bottom) so first drag does not jump. */
export const AI_FAB_DEFAULT_RIGHT = 14;
export const AI_FAB_DEFAULT_BOTTOM = 18;
export const AI_FAB_POS_KEY = 'cheesewaf-ai-fab-pos';

export function defaultFabPosition(size = AI_FAB_SIZE, margin = AI_FAB_MARGIN): FabPosition {
  if (typeof window === 'undefined') {
    return { left: margin, top: margin };
  }
  return {
    left: Math.max(margin, window.innerWidth - size - AI_FAB_DEFAULT_RIGHT),
    top: Math.max(margin, window.innerHeight - size - AI_FAB_DEFAULT_BOTTOM),
  };
}

export function clampFabPosition(pos: FabPosition, size = AI_FAB_SIZE, margin = AI_FAB_MARGIN): FabPosition {
  if (typeof window === 'undefined') {
    return pos;
  }
  const maxLeft = Math.max(margin, window.innerWidth - size - margin);
  const maxTop = Math.max(margin, window.innerHeight - size - margin);
  return {
    left: Math.min(maxLeft, Math.max(margin, pos.left)),
    top: Math.min(maxTop, Math.max(margin, pos.top)),
  };
}

export function loadFabPosition(): FabPosition | null {
  if (typeof window === 'undefined') {
    return null;
  }
  try {
    const raw = window.localStorage.getItem(AI_FAB_POS_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as Partial<FabPosition>;
    if (typeof parsed.left !== 'number' || typeof parsed.top !== 'number') {
      return null;
    }
    if (!Number.isFinite(parsed.left) || !Number.isFinite(parsed.top)) {
      return null;
    }
    return clampFabPosition({ left: parsed.left, top: parsed.top });
  } catch {
    return null;
  }
}

export function saveFabPosition(pos: FabPosition) {
  if (typeof window === 'undefined') {
    return;
  }
  try {
    window.localStorage.setItem(AI_FAB_POS_KEY, JSON.stringify(clampFabPosition(pos)));
  } catch {
    // ignore quota / private mode
  }
}
