import { writeFile } from 'node:fs/promises';
import { createInterface } from 'node:readline';

const PREFIX = 'CHEESEWAF_CAPTCHA_INTEGRATION ';
const [mode, output] = process.argv.slice(2);

if (mode === 'compile') {
  await writeFile(output, 'fixture control test binary');
} else if (mode === 'run') {
  reply({
    ok: true,
    ready: true,
    admin_url: 'http://127.0.0.1:41001',
    waf_url: 'http://127.0.0.1:41002',
    username: 'fixture-user',
    password: 'fixture-password',
  });
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    const request = JSON.parse(line);
    if (request.action === 'lab_plan') {
      const challenge = request.challenge;
      if (challenge?.type !== 'rotate' || challenge?.token !== 'sealed-token' || request.variant !== 'correct') {
        reply({ id: request.id, ok: false, error: 'invalid_lab_plan' });
        continue;
      }
      reply({ id: request.id, ok: true, plan: { interaction: 'range', action: { value: 4321 } } });
      continue;
    }
    if (request.action === 'shutdown') {
      reply({ id: request.id, ok: true });
      break;
    }
  }
} else {
  process.exitCode = 2;
}

function reply(value) {
  process.stdout.write(`${PREFIX}${JSON.stringify(value)}\n`);
}
