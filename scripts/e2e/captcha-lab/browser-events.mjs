export function observeBrowser(page, { verifyPath }) {
  const findings = [];
  page.on('console', (message) => { if (message.type() === 'error') findings.push('console'); });
  page.on('pageerror', () => findings.push('pageerror'));
  page.on('requestfailed', (request) => { const reason = request.failure()?.errorText ?? ''; if (!/ERR_ABORTED|NS_BINDING_ABORTED/i.test(reason)) findings.push('requestfailed'); });
  page.on('response', (response) => { const status = response.status(); const pathname = new URL(response.url()).pathname; if (status >= 400 && !(pathname === verifyPath && status === 410)) findings.push('http'); });
  return { assertClean(context) { if (findings.length) { const kinds = [...new Set(findings)].sort().join(','); throw new Error(`${context}: browser errors detected (${kinds})`); } } };
}
