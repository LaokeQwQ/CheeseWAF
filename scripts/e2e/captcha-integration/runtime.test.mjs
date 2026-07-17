import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startWebRuntime } from './runtime.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

test('web runtime proxies API and health routes to the supplied backend', async () => {
  const requests = [];
  const backend = createServer((request, response) => {
    requests.push(request.url);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ path: request.url }));
  });
  await listen(backend);
  const address = backend.address();
  assert.ok(address && typeof address !== 'string');

  const runtime = await startWebRuntime({
    projectRoot,
    apiTarget: `http://127.0.0.1:${address.port}`,
  });
  try {
    for (const pathname of ['/api/auth/login-options', '/health/ready']) {
      const response = await fetch(`${runtime.baseURL}${pathname}`);
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { path: pathname });
    }
    assert.deepEqual(requests, ['/api/auth/login-options', '/health/ready']);
  } finally {
    await runtime.close();
    await close(backend);
  }
});

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}
