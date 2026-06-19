export const preloadAIPage = () => import('../pages/AI/AIPage');

export const preloadAPISecurityPage = () => import('../pages/APISecurity/APISecurityPage');

export function preloadRoute(path: string) {
  if (path === '/ai') {
    void preloadAIPage();
  }
  if (path === '/apisec') {
    void preloadAPISecurityPage();
  }
}
