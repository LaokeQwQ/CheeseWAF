import { COORDINATE_MAX, clampCoordinate, toViewportPoint } from './surface.mjs';

export { COORDINATE_MAX, clampCoordinate, toViewportPoint };

export async function clickSurface(page, coordinateOrSelector, selectorOrCoordinate) {
  try {
    const { coordinate, selector } = resolveArguments(coordinateOrSelector, selectorOrCoordinate);
    const locator = resolveLocator(page, selector);
    if (typeof locator.waitFor === 'function') await locator.waitFor({ state: 'visible' });
    const box = await locator.boundingBox();
    if (!box) throw new Error('Click interaction failed');
    const viewport = toViewportPoint(box, coordinate);
    await page.mouse.click(viewport.x, viewport.y);
  } catch {
    throw new Error('Click interaction failed');
  }
}

export const clickPoint = clickSurface;

function resolveArguments(coordinateOrSelector, selectorOrCoordinate) {
  if (typeof coordinateOrSelector === 'string') return { coordinate: selectorOrCoordinate, selector: coordinateOrSelector };
  return { coordinate: coordinateOrSelector, selector: selectorOrCoordinate };
}

function resolveLocator(page, selector) {
  if (selector && typeof selector.boundingBox === 'function') return selector;
  if (!page || typeof page.locator !== 'function') throw new Error('Click interaction failed');
  return page.locator(selector);
}
