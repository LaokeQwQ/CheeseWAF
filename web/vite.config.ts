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
    rolldownOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) {
            return undefined;
          }
          if (id.includes('/react/') || id.includes('/react-dom/') || id.includes('/scheduler/')) {
            return 'vendor-react';
          }
          if (id.includes('/@arco-design/')) {
            return 'vendor-arco';
          }
          if (id.includes('/three/')) {
            return 'vendor-three';
          }
          if (id.includes('/echarts/') || id.includes('/d3-geo/') || id.includes('/topojson-client/') || id.includes('/world-atlas/')) {
            return 'vendor-visualization';
          }
          if (id.includes('/@tanstack/') || id.includes('/axios/') || id.includes('/i18next/') || id.includes('/react-i18next/') || id.includes('/zustand/')) {
            return 'vendor-runtime';
          }
          if (id.includes('/framer-motion/') || id.includes('/lucide-react/') || id.includes('/qrcode/')) {
            return 'vendor-ui-utils';
          }
          return 'vendor';
        },
      },
    },
  },
});
