import { describe, expect, it } from 'vitest';
import { matchesBackendProxyPath } from './vite.proxy';

describe('Vite API proxy path matching', () => {
  it.each([
    ['/api', true],
    ['/api/', true],
    ['/api/logs', true],
    ['/api/logs?limit=20', true],
    ['/health', true],
    ['/health/ready', true],
    ['/healthy', false],
    ['/apisec', false],
    ['/apisec/endpoints', false],
    ['/api-v2', false],
    ['/apiary', false],
  ])('matches %s only when it belongs to a backend route', (pathname, expected) => {
    expect(matchesBackendProxyPath(pathname)).toBe(expected);
  });
});
