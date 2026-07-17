import { describe, expect, it } from 'vitest';
import { safeImageDataUri } from './protocol';

describe('safeImageDataUri', () => {
  it.each([
    'data:image/png;base64,iVBORw0KGgo=',
    'data:image/jpeg;base64,/9j/4AAQSkZJRg==',
    'data:image/webp;base64,UklGRg==',
    'data:image/avif;base64,AAAAIGZ0eXA=',
  ])('accepts supported bitmap data URI %s', (value) => {
    expect(safeImageDataUri(value)).toBe(value);
  });

  it.each([
    'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=',
    'data:image/png,not-base64',
    'data:text/html;base64,PGgxPk5vPC9oMT4=',
    'https://example.test/captcha.png',
    'javascript:alert(1)',
  ])('rejects unsupported image source %s', (value) => {
    expect(safeImageDataUri(value)).toBeUndefined();
  });
});
