import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { codeInspectorPlugin } from '@agent-eyes/agent-eyes';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BACKEND_PROXY_PATTERN } from './vite.proxy';

const sourcemap = process.env.VITE_SOURCEMAP === 'true';
const projectRoot = fileURLToPath(new URL('.', import.meta.url));
const enableAgentEyes = process.env.NODE_ENV !== 'production' && process.env.CHEESEWAF_AGENT_EYES !== '0';

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(projectRoot, 'src'),
    },
  },
  plugins: [
    // code-inspector must register before @vitejs/plugin-react
    ...(enableAgentEyes
      ? [
          codeInspectorPlugin({
            bundler: 'vite',
            showSwitch: true,
            agent: {
              acp: { command: 'codex-acp' },
            },
          }),
        ]
      : []),
    react(),
    tailwindcss(),
  ],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: false,
    proxy: {
      [BACKEND_PROXY_PATTERN]: {
        target: process.env.VITE_DEV_API_TARGET || 'http://127.0.0.1:9443',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap,
    chunkSizeWarningLimit: 500,
    modulePreload: {
      resolveDependencies: (_filename, dependencies, context) =>
        context.hostType === 'html' ? dependencies.filter(isCriticalEntryPreload) : dependencies,
    },
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
          if (modulePath.includes('/@radix-ui/') || modulePath.includes('/class-variance-authority/') || modulePath.includes('/sonner/')) {
            return 'vendor-ui';
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
          if (modulePath.includes('/maplibre-gl/') || modulePath.includes('/@maplibre/') || modulePath.includes('/@mapbox/')) {
            return 'vendor-maplibre';
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

function isCriticalEntryPreload(dependency: string) {
  // Keep initial modulepreload under the 20 KiB gzip budget (vendor-react alone is ~45 KiB gzip).
  return dependency.includes('rolldown-runtime');
}
