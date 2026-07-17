import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const globalCSS = readFileSync('src/styles/global.css', 'utf8');

function ruleBody(selector: string, source = globalCSS) {
  const selectorStart = source.indexOf(selector);
  const bodyStart = source.indexOf('{', selectorStart);
  const bodyEnd = source.indexOf('}', bodyStart);
  expect(selectorStart, `missing CSS rule for ${selector}`).toBeGreaterThanOrEqual(0);
  expect(bodyStart).toBeGreaterThan(selectorStart);
  expect(bodyEnd).toBeGreaterThan(bodyStart);
  return source.slice(bodyStart + 1, bodyEnd);
}

describe('mobile AI assistant CSS', () => {
  it('keeps the panel above the bottom safe area and inside the usable viewport', () => {
    const mobileCSS = globalCSS.slice(globalCSS.indexOf('@media (max-width: 860px)'));
    const panel = ruleBody('.ai-assistant-panel', mobileCSS);

    expect(panel).toMatch(/bottom:\s*calc\([^;]*env\(safe-area-inset-bottom\)[^;]*\)/);
    expect(panel).toMatch(/max-height:\s*min\([^;]*env\(safe-area-inset-bottom\)[^;]*\)/);
  });

  it('provides a 44px close target without restoring close scaling', () => {
    const mobileCSS = globalCSS.slice(globalCSS.indexOf('@media (max-width: 860px)'));
    const closeButton = ruleBody('.assistant-close-button', mobileCSS);
    const closing = ruleBody('.ai-assistant-panel-closing');
    const animationStart = globalCSS.indexOf('@keyframes assistant-panel-out');
    const animationEnd = globalCSS.indexOf('@keyframes assistant-message-in', animationStart);
    const closingAnimation = globalCSS.slice(animationStart, animationEnd);

    expect(closeButton).toMatch(/width:\s*44px/);
    expect(closeButton).toMatch(/height:\s*44px/);
    expect(closing).not.toMatch(/scale\s*\(/);
    expect(animationStart).toBeGreaterThanOrEqual(0);
    expect(closingAnimation).not.toMatch(/scale\s*\(/);
  });
});
