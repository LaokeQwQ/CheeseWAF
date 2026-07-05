import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const sourcemap = process.env.VITE_SOURCEMAP === 'true';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: false,
  },
  build: {
    outDir: 'dist',
    sourcemap,
    chunkSizeWarningLimit: 600,
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
            return 'vendor-arco';
          }
          if (modulePath.includes('/three/build/') || modulePath.includes('/three/src/renderers/shaders/') || modulePath.includes('/three/src/renderers/webgl/')) {
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
          if (modulePath.includes('/lucide-react/') || modulePath.includes('/qrcode/')) {
            return 'vendor-ui-utils';
          }
          return 'vendor';
        },
      },
    },
  },
});
