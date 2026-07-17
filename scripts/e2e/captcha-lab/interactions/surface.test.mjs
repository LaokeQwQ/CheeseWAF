import assert from 'node:assert/strict';
import test from 'node:test';
import { clampCoordinate, drawSurface, toViewportPoint } from './surface.mjs';

const box = { x: 10, y: 20, width: 200, height: 100 };

test('maps normalized lower and upper boundaries to the surface edges', () => {
  assert.deepEqual(toViewportPoint(box, { x: 0, y: 0 }), { x: 10, y: 20 });
  assert.deepEqual(toViewportPoint(box, { x: 10_000, y: 10_000 }), { x: 210, y: 120 });
});

test('maps the normalized center to the viewport center', () => {
  assert.deepEqual(toViewportPoint(box, { x: 5_000, y: 5_000 }), { x: 110, y: 70 });
});

test('clamps normalized coordinates before conversion', () => {
  assert.equal(clampCoordinate(-500), 0);
  assert.equal(clampCoordinate(12_000), 10_000);
  assert.deepEqual(toViewportPoint(box, { x: -500, y: 12_000 }), { x: 10, y: 120 });
  assert.deepEqual(toViewportPoint(box, [-500, 12_000]), { x: 10, y: 120 });
});

test('draws a normalized path with physical mouse events', async () => {
  const events = [];
  const page = {
    locator(selector) {
      events.push(['locator', selector]);
      return {
        async waitFor(value) { events.push(['waitFor', value]); },
        async boundingBox() { events.push(['boundingBox']); return box; },
      };
    },
    mouse: {
      async move(x, y) { events.push(['move', x, y]); },
      async down() { events.push(['down']); },
      async up() { events.push(['up']); },
    },
    async waitForTimeout(value) { events.push(['wait', value]); },
  };

  await drawSurface(page, [{ x: 0, y: 0 }, { x: 5_000, y: 5_000 }, { x: 10_000, y: 10_000 }], '[data-testid="surface"]', { durationMs: 20 });

  assert.deepEqual(events, [
    ['locator', '[data-testid="surface"]'],
    ['waitFor', { state: 'visible' }],
    ['boundingBox'],
    ['move', 10, 20],
    ['down'],
    ['move', 110, 70],
    ['wait', 10],
    ['move', 210, 120],
    ['wait', 10],
    ['up'],
  ]);
});

test('hides implementation details when a surface operation fails', async () => {
  const page = {
    locator() {
      return { async boundingBox() { throw new Error('internal failure'); } };
    },
    mouse: { async up() {} },
  };

  await assert.rejects(
    drawSurface(page, [{ x: 9_001, y: 8_002 }], '[data-testid="surface"]', { durationMs: 0 }),
    (error) => error instanceof Error && error.message === 'Surface interaction failed' && !error.message.includes('9001'),
  );
});
