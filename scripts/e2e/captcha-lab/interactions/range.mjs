export async function dragRange(page, value, { durationMs = 180, thumbWidth = 42 } = {}) {
  const slider = page.getByRole('slider').first();
  await slider.waitFor({ state: 'visible' });
  const box = await slider.boundingBox();
  if (!box) throw new Error('CAPTCHA slider has no bounding box');
  const min = Number((await slider.getAttribute('min')) ?? 0);
  const max = Number((await slider.getAttribute('max')) ?? 10000);
  const target = Math.max(min, Math.min(max, Math.round(value)));
  const current = Number(await slider.inputValue());
  const span = Math.max(1, max - min);
  const travel = Math.max(1, box.width - Math.min(thumbWidth, box.width / 2));
  const center = (next) => box.x + Math.min(thumbWidth, box.width / 2) / 2 + ((next - min) / span) * travel;
  const y = box.y + box.height / 2;
  let pointerX = center(current);
  await page.mouse.move(pointerX, y);
  await page.mouse.down();
  const endX = center(target);
  const steps = Math.max(4, Math.ceil(durationMs / 30));
  for (let step = 1; step <= steps; step += 1) {
    pointerX += (endX - pointerX) / (steps - step + 1);
    await page.mouse.move(pointerX, y);
    await page.waitForTimeout(Math.ceil(durationMs / steps));
  }
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const actual = Number(await slider.inputValue());
    if (Math.abs(actual - target) <= rangeQuantizationTolerance(span, travel)) break;
    pointerX = Math.max(box.x, Math.min(box.x + box.width, pointerX + ((target - actual) / span) * travel));
    await page.mouse.move(pointerX, y);
    await page.waitForTimeout(16);
  }
  const actual = Number(await slider.inputValue());
  const tolerance = rangeQuantizationTolerance(span, travel);
  if (Math.abs(actual - target) > tolerance) {
    await page.mouse.up();
    throw new Error('CAPTCHA slider stopped outside its physical quantization tolerance');
  }
  await page.mouse.up();
}

export function rangeQuantizationTolerance(span, travel) {
  return Math.max(1, Math.ceil(span / Math.max(1, travel) / 2));
}
