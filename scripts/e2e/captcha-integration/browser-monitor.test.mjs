import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { monitorBrowser } from './browser-monitor.mjs';

test('browser monitor relies on the HTTP response policy for resource errors', () => {
  const page = new EventEmitter();
  const monitor = monitorBrowser(page, {
    allowHTTPError: (response) => response.status() === 401,
  });

  page.emit('response', response('/api/auth/captcha/verify', 401));
  page.emit('console', consoleMessage('error', 'Failed to load resource: the server responded with a status of 401 (Unauthorized)'));

  assert.doesNotThrow(() => monitor.assertClean('expected rejection'));
});

test('browser monitor still rejects unexpected HTTP and application console errors', () => {
  const httpPage = new EventEmitter();
  const httpMonitor = monitorBrowser(httpPage);
  httpPage.emit('response', response('/api/auth/captcha', 500));
  assert.throws(() => httpMonitor.assertClean('unexpected response'), /\(http\)/);

  const consolePage = new EventEmitter();
  const consoleMonitor = monitorBrowser(consolePage);
  consolePage.emit('console', consoleMessage('error', 'application invariant failed'));
  assert.throws(() => consoleMonitor.assertClean('console failure'), /\(console\)/);
});

function response(pathname, status) {
  return {
    url: () => `http://127.0.0.1${pathname}`,
    status: () => status,
    request: () => ({ method: () => 'POST' }),
  };
}

function consoleMessage(type, text) {
  return {
    type: () => type,
    text: () => text,
  };
}
