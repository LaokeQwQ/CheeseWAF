import assert from 'node:assert/strict';
import test from 'node:test';
import { clickSurface, toViewportPoint } from './click.mjs';

const box = { x: 30, y: 40, width: 400, height: 200 };

test('reuses normalized edge and center conversion for a click', () => {
  assert.deepEqual(toViewportPoint(box, { x: 0, y: 0 }), { x: 30, y: 40 });
  assert.deepEqual(toViewportPoint(box, { x: 5_000, y: 5_000 }), { x: 230, y: 140 });
  assert.deepEqual(toViewportPoint(box, { x: 10_000, y: 10_000 }), { x: 430, y: 240 });
});

test('clamps a click coordinate before sending it to the mouse', async () => {
  const calls = [];
  const page = {
    locator() {
      return { async boundingBox() { return box; } };
    },
    mouse: {
      async click(x, y) { calls.push([x, y]); },
    },
  };

  await clickSurface(page, { x: -1, y: 20_001 }, '[data-testid="surface"]');

  assert.deepEqual(calls, [[30, 240]]);
});

test('uses one physical mouse click at the converted location', async () => {
  const calls = [];
  const page = {
    locator(selector) {
      calls.push(['locator', selector]);
      return {
        async waitFor(value) { calls.push(['waitFor', value]); },
        async boundingBox() { calls.push(['boundingBox']); return box; },
      };
    },
    mouse: {
      async click(x, y) { calls.push(['click', x, y]); },
    },
  };

  await clickSurface(page, { x: 2_500, y: 7_500 }, '[data-testid="surface"]');

  assert.deepEqual(calls, [
    ['locator', '[data-testid="surface"]'],
    ['waitFor', { state: 'visible' }],
    ['boundingBox'],
    ['click', 130, 190],
  ]);
});

test('hides implementation details when a click operation fails', async () => {
  const page = {
    locator() {
      return { async boundingBox() { throw new Error('internal failure'); } };
    },
    mouse: { async click() {} },
  };

  await assert.rejects(
    clickSurface(page, { x: 1_234, y: 5_678 }, '[data-testid="surface"]'),
    (error) => error instanceof Error && error.message === 'Click interaction failed' && !error.message.includes('1234'),
  );
});
