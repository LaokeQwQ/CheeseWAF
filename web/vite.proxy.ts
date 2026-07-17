export const BACKEND_PROXY_PATTERN = '^/(?:api|health)(?:/|$)';

export function matchesBackendProxyPath(pathname: string) {
  return new RegExp(BACKEND_PROXY_PATTERN).test(pathname);
}
