import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { configDefaults, defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

const projectRoot = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(projectRoot, 'src'),
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    // scripts/*.test.mjs are written against node:test and are run by
    // `npm run test:scripts`. Vitest cannot bundle node:test built-ins, so
    // keep them out of the jsdom run.
    exclude: [...configDefaults.exclude, 'scripts/**'],
    // Fork per file so CSSTransition timers cannot fire after another suite tears down jsdom.
    pool: 'forks',
    isolate: true,
    fileParallelism: false,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      reportsDirectory: './coverage',
      include: ['src/**/*.{ts,tsx}'],
      thresholds: {
        lines: 27,
        functions: 15,
        statements: 27,
        branches: 22,
      },
    },
  },
});
