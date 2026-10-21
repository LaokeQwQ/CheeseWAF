import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { compile } from 'tailwindcss';

const readSource = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8');

test('destructive button foreground generates a Tailwind color utility', async () => {
  const stylesheet = readSource('styles/shadcn.css');
  const theme = stylesheet.match(/@theme inline\s*\{[^}]+\}/)?.[0];
  assert.ok(theme, 'Tailwind theme is required');
  const compiler = await compile(`${theme}\n@tailwind utilities;`);
  const output = compiler.build(['bg-destructive', 'text-destructive-foreground']);
  assert.match(output, /\.bg-destructive\s*\{\s*background-color:\s*var\(--destructive\)/);
  assert.match(output, /\.text-destructive-foreground\s*\{\s*color:\s*var\(--destructive-foreground\)/);
});

test('small error trace text retains readable contrast in every theme', () => {
  const stylesheet = readSource('styles/global.css');
  const foregroundToken = stylesheet.match(/\.ui-error-trace code\s*\{\s*color:\s*var\((--[\w-]+)\)/)?.[1];
  const backgroundToken = stylesheet.match(/\.ui-error-detail,\s*\.ui-error-trace\s*\{[^}]*background:\s*var\((--[\w-]+)\)/)?.[1];
  assert.ok(foregroundToken, 'trace text color token is required');
  assert.ok(backgroundToken, 'trace panel background token is required');
  for (const theme of ['light', 'dark', 'blue-white', 'black-gold', 'miku-green', 'pink-white']) {
    const source = readSource(`themes/${theme}.css`);
    const foreground = resolveThemeColor(source, foregroundToken);
    const background = resolveThemeColor(source, backgroundToken);
    const ratio = contrast(foreground, background);
    assert.ok(ratio >= 4.5, `${theme}: ${foreground} on ${background} contrast ${ratio.toFixed(3)} is below 4.5`);
  }
});

function resolveThemeColor(source, token) {
  const values = new Map([...source.matchAll(/(--[\w-]+):\s*([^;]+);/g)].map((match) => [match[1], match[2].trim()]));
  for (let depth = 0; depth < 8; depth++) {
    const value = values.get(token);
    assert.ok(value, `theme token ${token} is missing`);
    if (/^#[\da-f]{6}$/i.test(value)) return value;
    const reference = value.match(/^var\((--[\w-]+)\)$/);
    assert.ok(reference, `unsupported color value for ${token}: ${value}`);
    token = reference[1];
  }
  assert.fail(`theme token ${token} contains a reference cycle`);
}

function contrast(first, second) {
  const luminance = (hex) => {
    const channels = hex.slice(1).match(/../g).map((byte) => parseInt(byte, 16) / 255)
      .map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
    return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
  };
  const firstLuminance = luminance(first);
  const secondLuminance = luminance(second);
  return (Math.max(firstLuminance, secondLuminance) + 0.05) / (Math.min(firstLuminance, secondLuminance) + 0.05);
}
