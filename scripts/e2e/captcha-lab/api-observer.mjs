export function observeCaptchaAPI(page, config) {
  const issued = [], verified = [];
  page.on('response', async (response) => { const pathname = new URL(response.url()).pathname; if (pathname !== config.issuePath && pathname !== config.verifyPath) return; let body; try { body = await response.json(); } catch { body = undefined; } const record = { status: response.status(), body, request: parseRequest(response.request().postData()), recordedAt: Date.now() }; (pathname === config.issuePath ? issued : verified).push(record); });
  return { nextIssue: (after = 0) => waitForRecord(issued, after, config.timeoutMs, 'challenge issue'), nextVerify: (after = 0) => waitForRecord(verified, after, config.timeoutMs, 'challenge verify'), issueCount: () => issued.length, verifyCount: () => verified.length };
}
function parseRequest(raw) { if (!raw) return undefined; try { return JSON.parse(raw); } catch { return raw; } }
async function waitForRecord(records, after, timeoutMs, label) { const deadline = Date.now() + timeoutMs; while (Date.now() < deadline) { if (records.length > after) return records[after]; await new Promise((resolve) => setTimeout(resolve, 25)); } throw new Error(`Timed out waiting for ${label}`); }
export function unwrapData(record) { return record?.body?.data ?? record?.body; }
