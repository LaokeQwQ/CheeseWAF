const COORDINATE_MAX = 10_000;

export async function dragLoginSlider(page, target, maximum, durationMs) {
  const thumb = page.locator('.auth-slider-thumb[role="slider"]');
  const track = page.locator('.auth-slider-track');
  await thumb.waitFor({ state: 'visible' });
  await thumb.hover();
  const [thumbBox, trackBox] = await Promise.all([thumb.boundingBox(), track.boundingBox()]);
  if (!thumbBox || !trackBox || maximum <= 0) throw new Error('login slider geometry is unavailable');
  const renderedTravel = trackBox.width - thumbBox.width;
  if (renderedTravel <= 0) throw new Error('login slider travel is unavailable');
  const start = { x: thumbBox.x + thumbBox.width / 2, y: thumbBox.y + thumbBox.height / 2 };
  const end = {
    x: trackBox.x + thumbBox.width / 2 + (clamp(target, 0, maximum) / maximum) * renderedTravel,
    y: start.y,
  };
  let pressed = false;
  try {
    await page.mouse.move(start.x, start.y);
    await page.mouse.down();
    pressed = true;
    await page.locator('.auth-slider-dragging').waitFor({ state: 'visible', timeout: 2_000 });
    await movePointer(page, start, end, durationMs, 12);
    await page.mouse.up();
    pressed = false;
  } finally {
    if (pressed) {
      try {
        await page.mouse.up();
      } catch {
        // Keep the original interaction failure.
      }
    }
  }
}

export async function dragWAFShape(page, targetX, targetY, durationMs) {
  const surface = page.locator('#interaction-overlay');
  await surface.waitFor({ state: 'visible' });
  const box = await surface.boundingBox();
  if (!box) throw new Error('WAF challenge surface is unavailable');
  const start = normalizedPoint(box, 1400, targetY);
  const end = normalizedPoint(box, targetX, targetY);
  await dragPointer(page, start, end, durationMs, 14);
}

async function dragPointer(page, start, end, durationMs, steps) {
  const stepDuration = Math.max(12, Math.ceil(durationMs / steps));
  let pressed = false;
  try {
    await page.mouse.move(start.x, start.y);
    await page.mouse.down();
    pressed = true;
    await movePointer(page, start, end, durationMs, steps, stepDuration);
    await page.mouse.up();
    pressed = false;
  } finally {
    if (pressed) {
      try {
        await page.mouse.up();
      } catch {
        // Keep the original interaction failure.
      }
    }
  }
}

async function movePointer(page, start, end, durationMs, steps, explicitStepDuration) {
  const stepDuration = explicitStepDuration ?? Math.max(12, Math.ceil(durationMs / steps));
  for (let index = 1; index <= steps; index += 1) {
    const progress = index / steps;
    await page.mouse.move(
      start.x + (end.x - start.x) * progress,
      start.y + (end.y - start.y) * progress,
    );
    await page.waitForTimeout(stepDuration);
  }
}

function normalizedPoint(box, x, y) {
  return {
    x: box.x + (clamp(x, 0, COORDINATE_MAX) / COORDINATE_MAX) * box.width,
    y: box.y + (clamp(y, 0, COORDINATE_MAX) / COORDINATE_MAX) * box.height,
  };
}

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, Number(value)));
}
