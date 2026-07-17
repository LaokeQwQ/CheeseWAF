export function monitorBrowser(page, { allowHTTPError = () => false } = {}) {
  const findings = [];
  const counters = new Map();

  page.on('console', (message) => {
    if (message.type() === 'error') {
      // Chromium mirrors failed HTTP responses to the console. The response
      // listener below applies the route-specific allowlist and is authoritative.
      if (/^Failed to load resource: the server responded with a status of \d+/i.test(message.text())) return;
      findings.push('console');
      debugFinding('console', message.text());
    }
  });
  page.on('pageerror', (error) => {
    findings.push('pageerror');
    debugFinding('pageerror', error instanceof Error ? error.message : String(error));
  });
  page.on('requestfailed', (request) => {
    const reason = request.failure()?.errorText ?? '';
    if (!/ERR_ABORTED|NS_BINDING_ABORTED/i.test(reason)) findings.push('requestfailed');
  });
  page.on('response', (response) => {
    const pathname = new URL(response.url()).pathname;
    const key = `${response.request().method()} ${pathname}`;
    counters.set(key, (counters.get(key) ?? 0) + 1);
    if (response.status() >= 400) {
      debugFinding('http', `${key} ${response.status()}`);
      if (!allowHTTPError(response)) findings.push('http');
    }
  });

  return {
    count(method, pathname) {
      return counters.get(`${method.toUpperCase()} ${pathname}`) ?? 0;
    },
    assertClean(label) {
      if (findings.length === 0) return;
      const categories = [...new Set(findings)].sort().join(',');
      throw new Error(`${label}: browser errors detected (${categories})`);
    },
  };
}

function debugFinding(category, value) {
  if (process.env.CAPTCHA_E2E_DEBUG !== '1') return;
  const message = String(value ?? '')
    .replace(/https?:\/\/[^\s)]+/gi, '<url>')
    .replace(/[A-Za-z0-9_-]{80,}/g, '<opaque>')
    .slice(0, 240);
  console.error(`CAPTCHA browser ${category}: ${message}`);
}

export function responseMatches(pathname, { method, status } = {}) {
  return (response) => {
    const url = new URL(response.url());
    if (url.pathname !== pathname) return false;
    if (method && response.request().method() !== method.toUpperCase()) return false;
    return status == null || response.status() === status;
  };
}

export async function responseData(response) {
  const body = await response.json();
  return body?.data ?? body;
}
