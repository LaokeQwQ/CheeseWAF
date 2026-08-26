import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadGaodeWorldCollection } from './worldBoundaries';

describe('loadGaodeWorldCollection', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('throws when the world map request fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('missing', { status: 404 })));
    await expect(loadGaodeWorldCollection()).rejects.toThrow(/Failed to fetch Gaode world map: 404/);
  });

  it('throws when DecompressionStream is unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('gzip-bytes', { status: 200 })));
    vi.stubGlobal('DecompressionStream', undefined);
    await expect(loadGaodeWorldCollection()).rejects.toThrow(/DecompressionStream is unavailable/);
  });
});
