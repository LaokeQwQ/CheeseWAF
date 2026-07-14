export const preloadAIPage = () => import('../pages/AI/AIPage');
export const preloadAPISecurityPage = () => import('../pages/APISecurity/APISecurityPage');
export const preloadAttackMapPage = () => import('../pages/AttackMap/AttackMapPage');
export const preloadAttackScreenPage = () => import('../pages/AttackMap/AttackScreenPage');
export const preloadGlobeMap = () => import('../pages/AttackMap/GlobeMap');

type RouteLoader = () => Promise<unknown>;

const routeLoaders: Record<string, RouteLoader> = {
  '/': () => import('../pages/Dashboard/DashboardPage'),
  '/sites': () => import('../pages/Sites/SitesPage'),
  '/ssl': () => import('../pages/SSL/SSLPage'),
  '/rules': () => import('../pages/Rules/RulesPage'),
  '/logs': () => import('../pages/Logs/LogsPage'),
  '/ip': () => import('../pages/IPManage/IPManagePage'),
  '/protection': () => import('../pages/Protection/ProtectionPage'),
  '/bot-challenge': () => import('../pages/BotChallenge/BotChallengePage'),
  '/apisec': preloadAPISecurityPage,
  '/ai': preloadAIPage,
  '/monitor': () => import('../pages/Monitor/MonitorPage'),
  '/attack-map': preloadAttackMapPage,
  '/edge': () => import('../pages/Edge/EdgePage'),
  '/block-pages': () => import('../pages/BlockPages/BlockPagesPage'),
  '/users': () => import('../pages/Users/UsersPage'),
  '/ops': () => import('../pages/Operations/OperationsPage'),
  '/updates': () => import('../pages/Updates/UpdatesPage'),
  '/cluster': () => import('../pages/Cluster/ClusterPage'),
  '/system': () => import('../pages/System/SystemPage'),
  '/attack-map/screen': async () => {
    await Promise.all([preloadAttackScreenPage(), preloadGlobeMap()]);
  },
};

const pendingPreloads = new Map<string, Promise<unknown>>();

export function preloadRoute(path: string) {
  const loader = routeLoaders[path];
  if (!loader || pendingPreloads.has(path)) {
    return;
  }
  const pending = loader().catch(() => undefined).finally(() => pendingPreloads.delete(path));
  pendingPreloads.set(path, pending);
}
