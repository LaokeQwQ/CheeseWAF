import { clickSurface } from './click.mjs';
import { dragRange } from './range.mjs';
import { drawSurface } from './surface.mjs';

export async function solveScenario(page, challenge, operation) {
  await page.locator('section[data-status="ready"]').first().waitFor({ state: 'visible' });
  if (!operation || !operation.action) throw new Error('CAPTCHA interaction is unavailable');
  switch (operation.interaction) {
    case 'range':
      if (!Number.isFinite(operation.action.value)) throw new Error('CAPTCHA range interaction is unavailable');
      await dragRange(page, operation.action.value);
      return;
    case 'surface': {
      const selector = challenge?.type === 'curve_draw' ? '[data-testid="curve-draw-surface"]' : '[data-testid="scratch-challenge"]';
      const surface = page.locator(`${selector}[aria-disabled="false"]`);
      await surface.waitFor({ state: 'visible' });
      await drawSurface(page, operation.action.path, surface);
      return;
    }
    case 'click': {
      const kind = challenge?.type === 'text_click' ? 'text-click-challenge' : 'icon-click-challenge';
      const surface = page.locator(`[data-testid="captcha-surface"][data-challenge-type="${kind}"][aria-disabled="false"]`);
      await surface.waitFor({ state: 'visible' });
      await clickSurface(page, operation.action.at, surface);
      const submit = page.locator('section[data-status="interacting"] button:not([title])').last();
      await submit.click();
      return;
    }
    default:
      throw new Error('CAPTCHA interaction kind is unavailable');
  }
}
