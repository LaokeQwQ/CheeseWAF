export const COORDINATE_MAX = 10_000;
export const DEFAULT_DURATION_MS = 240;

export function clampCoordinate(value) {
  const numeric = Number(value);
  if (Number.isNaN(numeric)) return 0;
  return Math.max(0, Math.min(COORDINATE_MAX, numeric));
}

export function toViewportPoint(first, second) {
  const firstIsBox = isBoundingBox(first);
  const box = firstIsBox ? first : second;
  const coordinate = firstIsBox ? second : first;
  if (!isBoundingBox(box) || !isCoordinate(coordinate)) throw new Error('Coordinate conversion failed');

  const x = finiteNumber(box.x ?? 0);
  const y = finiteNumber(box.y ?? 0);
  const width = finiteNumber(box.width);
  const height = finiteNumber(box.height);
  if (x === undefined || y === undefined || width === undefined || height === undefined || width < 0 || height < 0) {
    throw new Error('Coordinate conversion failed');
  }

  return {
    x: x + (clampCoordinate(coordinateValue(coordinate, 'x', 0)) / COORDINATE_MAX) * width,
    y: y + (clampCoordinate(coordinateValue(coordinate, 'y', 1)) / COORDINATE_MAX) * height,
  };
}

export function normalizeSurfacePath(path) {
  if (!Array.isArray(path) || path.length === 0) throw new Error('Surface interaction failed');
  return path.map((entry) => {
    if (!isCoordinate(entry)) throw new Error('Surface interaction failed');
    return { x: clampCoordinate(coordinateValue(entry, 'x', 0)), y: clampCoordinate(coordinateValue(entry, 'y', 1)) };
  });
}

export async function drawSurface(page, pathOrSelector, selectorOrPath, options = {}) {
  let pressed = false;
  try {
    const { path, selector } = resolveArguments(pathOrSelector, selectorOrPath);
    const normalizedPath = normalizeSurfacePath(path);
    const locator = resolveLocator(page, selector);
    if (typeof locator.waitFor === 'function') await locator.waitFor({ state: 'visible' });
    const box = await locator.boundingBox();
    if (!box) throw new Error('Surface interaction failed');
    const viewportPath = normalizedPath.map((coordinate) => toViewportPoint(box, coordinate));
    const durationMs = normalizedDuration(options);
    const durations = segmentDurations(normalizedPath, durationMs);

    await page.mouse.move(viewportPath[0].x, viewportPath[0].y);
    await page.mouse.down();
    pressed = true;
    if (viewportPath.length === 1) {
      await waitForDuration(page, durations[0]);
    } else {
      for (let index = 1; index < viewportPath.length; index += 1) {
        const coordinate = viewportPath[index];
        await page.mouse.move(coordinate.x, coordinate.y);
        await waitForDuration(page, durations[index - 1]);
      }
    }
    await page.mouse.up();
    pressed = false;
  } catch {
    if (pressed) {
      try {
        await page.mouse.up();
      } catch {
        // Preserve the generic interaction error.
      }
    }
    throw new Error('Surface interaction failed');
  }
}

export const dragSurface = drawSurface;

function resolveArguments(pathOrSelector, selectorOrPath) {
  if (typeof pathOrSelector === 'string') return { path: selectorOrPath, selector: pathOrSelector };
  return { path: pathOrSelector, selector: selectorOrPath };
}

function resolveLocator(page, selector) {
  if (selector && typeof selector.boundingBox === 'function') return selector;
  if (!page || typeof page.locator !== 'function') throw new Error('Surface interaction failed');
  return page.locator(selector);
}

function isBoundingBox(value) {
  return Boolean(value && typeof value === 'object' && 'width' in value && 'height' in value);
}

function isCoordinate(value) {
  if (Array.isArray(value)) return value.length >= 2;
  return Boolean(value && typeof value === 'object' && 'x' in value && 'y' in value);
}

function coordinateValue(value, key, index) {
  return Array.isArray(value) ? value[index] : value[key];
}

function finiteNumber(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : undefined;
}

function normalizedDuration(options) {
  const raw = typeof options === 'number' ? options : options?.durationMs ?? options?.duration ?? DEFAULT_DURATION_MS;
  const numeric = Number(raw);
  return Number.isFinite(numeric) ? Math.max(0, Math.round(numeric)) : DEFAULT_DURATION_MS;
}

function segmentDurations(path, durationMs) {
  const count = Math.max(1, path.length - 1);
  if (count === 1 && path.length === 1) return [durationMs];
  if (durationMs === 0) return Array(count).fill(0);

  const lengths = [];
  for (let index = 1; index < path.length; index += 1) {
    const dx = path[index].x - path[index - 1].x;
    const dy = path[index].y - path[index - 1].y;
    lengths.push(Math.hypot(dx, dy));
  }
  const total = lengths.reduce((sum, length) => sum + length, 0);
  const durations = [];
  let elapsed = 0;
  for (let index = 0; index < count; index += 1) {
    const share = total > 0 ? lengths[index] / total : 1 / count;
    const next = index === count - 1 ? durationMs : Math.round(elapsed + durationMs * share);
    durations.push(Math.max(0, next - elapsed));
    elapsed = next;
  }
  return durations;
}

async function waitForDuration(page, durationMs) {
  if (durationMs <= 0) return;
  if (typeof page.waitForTimeout === 'function') {
    await page.waitForTimeout(durationMs);
    return;
  }
  await new Promise((resolve) => setTimeout(resolve, durationMs));
}
