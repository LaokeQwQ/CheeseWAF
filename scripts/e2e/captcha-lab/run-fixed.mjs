import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runFixedHarness } from './fixed-harness.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const report = await runFixedHarness({ cwd: projectRoot });
console.log(`PASS fixed CAPTCHA harness (${report.map((item) => item.type).join(', ')})`);
