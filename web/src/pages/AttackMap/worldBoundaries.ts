import type { GeoFeatureCollection } from './attackMapData';

const emptyWorld: GeoFeatureCollection = { type: 'FeatureCollection', features: [] };

export async function loadGaodeWorldCollection(signal?: AbortSignal): Promise<GeoFeatureCollection> {
  const base = (import.meta.env.BASE_URL || '/').replace(/\/?$/, '/');
  const url = `${base}map/world/gaode_world.geojson.gz`;
  const response = await fetch(url, { headers: { Accept: 'application/json' }, signal });
  if (!response.ok) {
    throw new Error(`Failed to fetch Gaode world map: ${response.status}`);
  }
  const body = response.body;
  if (!body || typeof DecompressionStream === 'undefined') {
    return emptyWorld;
  }
  const decompressed = body.pipeThrough(new DecompressionStream('gzip'));
  const collection = await new Response(decompressed).json() as GeoFeatureCollection;
  if (!collection || collection.type !== 'FeatureCollection' || !Array.isArray(collection.features)) {
    return emptyWorld;
  }
  return collection;
}
