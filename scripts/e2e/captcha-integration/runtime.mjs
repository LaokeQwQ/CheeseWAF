import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const BACKEND_PROXY_PATTERN = '^/(?:api|health)(?:/|$)';

export async function startWebRuntime({ projectRoot, apiTarget }) {
  const webRoot = path.join(projectRoot, 'web');
  const requireFromWeb = createRequire(path.join(webRoot, 'package.json'));
  const viteModule = await import(pathToFileURL(requireFromWeb.resolve('vite')).href);
  const server = await viteModule.createServer({
    root: webRoot,
    configFile: path.join(webRoot, 'vite.config.ts'),
    clearScreen: false,
    logLevel: 'silent',
    server: {
      host: '127.0.0.1',
      port: 0,
      strictPort: true,
      proxy: {
        // This key must replace the matching proxy entry from vite.config.ts.
        [BACKEND_PROXY_PATTERN]: { target: apiTarget, changeOrigin: true },
      },
    },
  });
  await server.listen();
  const address = server.httpServer?.address();
  if (!address || typeof address === 'string') {
    await server.close();
    throw new Error('CAPTCHA integration web runtime did not bind a local port');
  }
  return {
    baseURL: `http://127.0.0.1:${address.port}`,
    close: () => server.close(),
  };
}

export async function loadChromium(projectRoot) {
  const webRoot = path.join(projectRoot, 'web');
  const requireFromWeb = createRequire(path.join(webRoot, 'package.json'));
  const module = await import(pathToFileURL(requireFromWeb.resolve('playwright')).href);
  const playwright = module.default ?? module;
  if (!playwright.chromium) throw new Error('Playwright Chromium is unavailable');
  return playwright.chromium;
}
