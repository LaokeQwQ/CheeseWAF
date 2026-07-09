import { defineConfig } from 'vite';
import type { Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { copyFileSync, createReadStream, existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import type { ServerResponse } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const sourcemap = process.env.VITE_SOURCEMAP === 'true';
const projectRoot = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  plugins: [react(), chinaMapStaticAssets()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: false,
  },
  build: {
    outDir: 'dist',
    sourcemap,
    chunkSizeWarningLimit: 500,
    rolldownOptions: {
      output: {
        manualChunks(id) {
          const modulePath = id.replace(/\\/g, '/');
          if (!modulePath.includes('node_modules')) {
            return undefined;
          }
          if (modulePath.includes('/react/') || modulePath.includes('/react-dom/') || modulePath.includes('/scheduler/')) {
            return 'vendor-react';
          }
          if (modulePath.includes('/@arco-design/')) {
            return arcoChunk(modulePath);
          }
          if (modulePath.includes('/three/src/renderers/shaders/') || modulePath.includes('/three/src/renderers/webgl/') || modulePath.includes('/three/src/renderers/WebGL')) {
            return 'vendor-three-webgl';
          }
          if (modulePath.includes('/three/src/renderers/')) {
            return 'vendor-three-renderer';
          }
          if (modulePath.includes('/three/src/materials/') || modulePath.includes('/three/src/geometries/') || modulePath.includes('/three/src/textures/')) {
            return 'vendor-three-scene';
          }
          if (modulePath.includes('/three/src/')) {
            return 'vendor-three-core';
          }
          if (modulePath.includes('/d3-geo/') || modulePath.includes('/topojson-client/') || modulePath.includes('/world-atlas/')) {
            return 'vendor-visualization';
          }
          if (modulePath.includes('/@tanstack/') || modulePath.includes('/axios/') || modulePath.includes('/i18next/') || modulePath.includes('/react-i18next/') || modulePath.includes('/zustand/')) {
            return 'vendor-runtime';
          }
          if (modulePath.includes('/qrcode/')) {
            return 'vendor-qrcode';
          }
          if (modulePath.includes('/lucide-react/')) {
            return 'vendor-ui-utils';
          }
          return 'vendor';
        },
      },
    },
  },
});

function arcoChunk(modulePath: string) {
  const lowerPath = modulePath.toLowerCase();
  if (
    lowerPath.includes('/table') ||
    lowerPath.includes('/pagination') ||
    lowerPath.includes('/virtual-list') ||
    lowerPath.includes('/resize-box')
  ) {
    return 'vendor-arco-data';
  }
  if (
    lowerPath.includes('/form') ||
    lowerPath.includes('/input') ||
    lowerPath.includes('/input-number') ||
    lowerPath.includes('/select') ||
    lowerPath.includes('/date-picker') ||
    lowerPath.includes('/time-picker') ||
    lowerPath.includes('/checkbox') ||
    lowerPath.includes('/radio') ||
    lowerPath.includes('/switch') ||
    lowerPath.includes('/upload') ||
    lowerPath.includes('/cascader')
  ) {
    return 'vendor-arco-form';
  }
  if (
    lowerPath.includes('/modal') ||
    lowerPath.includes('/drawer') ||
    lowerPath.includes('/popover') ||
    lowerPath.includes('/popconfirm') ||
    lowerPath.includes('/dropdown') ||
    lowerPath.includes('/tooltip') ||
    lowerPath.includes('/message') ||
    lowerPath.includes('/notification') ||
    lowerPath.includes('/trigger') ||
    lowerPath.includes('/tabs') ||
    lowerPath.includes('/steps')
  ) {
    return 'vendor-arco-overlay';
  }
  return 'vendor-arco-core';
}

function chinaMapStaticAssets(): Plugin {
  const chinaMapRoutePrefix = '/china-map-echarts/map/';
  const chinaMapManifestName = 'index.json';
  const adminRoutePrefix = '/province-city-china/';
  const chinaMapSourceDir = path.join(projectRoot, 'node_modules', 'china-map-echarts', 'map');
  const chinaMapOutputDir = path.join(projectRoot, 'dist', 'china-map-echarts', 'map');
  const adminFiles = [
    {
      route: 'province/province.json',
      source: path.join(projectRoot, 'node_modules', '@province-city-china', 'province', 'province.json'),
      output: path.join(projectRoot, 'dist', 'province-city-china', 'province', 'province.json'),
    },
    {
      route: 'city/city.json',
      source: path.join(projectRoot, 'node_modules', '@province-city-china', 'city', 'city.json'),
      output: path.join(projectRoot, 'dist', 'province-city-china', 'city', 'city.json'),
    },
    {
      route: 'area/area.json',
      source: path.join(projectRoot, 'node_modules', '@province-city-china', 'area', 'area.json'),
      output: path.join(projectRoot, 'dist', 'province-city-china', 'area', 'area.json'),
    },
  ];

  return {
    name: 'cheesewaf-china-map-static-assets',
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        const url = request.url ?? '';
        if (url.startsWith(chinaMapRoutePrefix)) {
          const filename = decodeURIComponent(url.slice(chinaMapRoutePrefix.length).split(/[?#]/, 1)[0] ?? '');
          if (filename === chinaMapManifestName) {
            sendJSONValue(listChinaMapAdcodes(chinaMapSourceDir), response);
            return;
          }
          if (!/^\d{6}\.json$/.test(filename)) {
            sendStaticNotFound(response);
            return;
          }
          const filePath = path.join(chinaMapSourceDir, filename);
          if (!filePath.startsWith(chinaMapSourceDir) || !existsSync(filePath)) {
            sendStaticNotFound(response);
            return;
          }
          sendJSONFile(filePath, response);
          return;
        }

        if (url.startsWith(adminRoutePrefix)) {
          const requested = decodeURIComponent(url.slice(adminRoutePrefix.length).split(/[?#]/, 1)[0] ?? '');
          const match = adminFiles.find((item) => item.route === requested);
          if (!match || !existsSync(match.source)) {
            sendStaticNotFound(response);
            return;
          }
          sendJSONFile(match.source, response);
          return;
        }

        next();
      });
    },
    closeBundle() {
      if (existsSync(chinaMapSourceDir)) {
        rmSync(chinaMapOutputDir, { force: true, recursive: true });
        mkdirSync(chinaMapOutputDir, { recursive: true });
        for (const filename of readdirSync(chinaMapSourceDir)) {
          if (/^\d{6}\.json$/.test(filename)) {
            copyFileSync(path.join(chinaMapSourceDir, filename), path.join(chinaMapOutputDir, filename));
          }
        }
        writeFileSync(path.join(chinaMapOutputDir, chinaMapManifestName), JSON.stringify(listChinaMapAdcodes(chinaMapSourceDir), null, 2));
      }
      for (const item of adminFiles) {
        if (existsSync(item.source)) {
          mkdirSync(path.dirname(item.output), { recursive: true });
          copyFileSync(item.source, item.output);
        }
      }
    },
  };
}

function sendJSONFile(filePath: string, response: ServerResponse) {
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'public, max-age=3600');
  createReadStream(filePath).pipe(response);
}

function sendJSONValue(value: unknown, response: ServerResponse) {
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'public, max-age=3600');
  response.end(JSON.stringify(value));
}

function sendStaticNotFound(response: ServerResponse) {
  response.statusCode = 404;
  response.end('Not found');
}

function listChinaMapAdcodes(sourceDir: string) {
  if (!existsSync(sourceDir)) {
    return [];
  }
  return readdirSync(sourceDir)
    .filter((filename) => /^\d{6}\.json$/.test(filename))
    .map((filename) => filename.slice(0, -'.json'.length))
    .sort();
}
