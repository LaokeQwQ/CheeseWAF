import type { GeoFeatureCollection } from './attackMapData';

export async function loadGaodeWorldCollection(signal?: AbortSignal): Promise<GeoFeatureCollection> {
  const base = (import.meta.env.BASE_URL || '/').replace(/\/?$/, '/');
  const url = `${base}map/world/gaode_world.geojson.gz`;
  const response = await fetch(url, { headers: { Accept: 'application/json' }, signal });
  if (!response.ok) {
    throw new Error(`Failed to fetch Gaode world map: ${response.status}`);
  }
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('DecompressionStream is unavailable; cannot decompress the Gaode world map');
  }
  const body = response.body;
  if (!body) {
    throw new Error('No response body for the Gaode world map');
  }
  const decompressed = body.pipeThrough(new DecompressionStream('gzip'));
  const collection = await new Response(decompressed).json() as GeoFeatureCollection;
  if (!collection || collection.type !== 'FeatureCollection' || !Array.isArray(collection.features)) {
    throw new Error('Invalid Gaode world map payload');
  }
  return collection;
}
