declare module '@agent-eyes/agent-eyes' {
  import type { Plugin } from 'vite';

  /** Dev-only code inspector; published package may omit .d.ts when install scripts are skipped. */
  export function codeInspectorPlugin(options?: Record<string, unknown>): Plugin;
}
