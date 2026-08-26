import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));

describe('offline attack map sources', () => {
  it('does not embed public raster tile CDNs', () => {
    const files = [
      'OsmAttackMap.tsx',
      'AttackMapPage.tsx',
      'GlobeMap.tsx',
      'chinaBoundaries.ts',
      'attackMapData.ts',
    ];
    const blocked = [
      'tile.openstreetmap.org',
      'openstreetmap.org/{z}',
      'openfreemap.org',
      'api.mapbox.com',
      'maptiler.com',
    ];
    for (const file of files) {
      const text = readFileSync(join(here, file), 'utf8');
      for (const needle of blocked) {
        expect(text, `${file} must not contain ${needle}`).not.toContain(needle);
      }
    }
  });
});
