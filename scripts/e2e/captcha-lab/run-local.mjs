import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startWebRuntime } from '../captcha-integration/runtime.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const runtime = await startWebRuntime({ projectRoot, apiTarget: 'http://127.0.0.1:1' });
process.env.CAPTCHA_E2E_BASE_URL ??= runtime.baseURL;
process.env.CAPTCHA_E2E_TOKEN ??= 'local-captcha-e2e-session';

try {
  await import(`./run.mjs?local=${Date.now()}`);
} finally {
  await runtime.close();
}
