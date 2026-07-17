import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      reportsDirectory: './coverage',
      include: [
        'src/api/client.ts',
        'src/themes/index.ts',
        'src/pages/AI/AIPage.tsx',
        'src/pages/Updates/UpdatesPage.tsx',
      ],
      thresholds: {
        lines: 27,
        functions: 15,
        statements: 27,
        branches: 22,
      },
    },
  },
});
