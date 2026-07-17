import { describe, expect, it } from 'vitest';
import { mergeRecoveredApprovals } from './AIAssistant';
import type { AIApprovalRequest } from '../../types/api';

const t = (key: string, options?: Record<string, unknown>) => String(options?.defaultValue ?? key);

function approval(id: string, status: string): AIApprovalRequest {
  return {
    id,
    tool_name: 'set_protection_level',
    args: { level: 'smart' },
    sensitivity: 'modify',
    status,
    created_at: '2026-07-11T08:00:00Z',
    expires_at: '2026-07-11T09:00:00Z',
  };
}

describe('AI approval recovery', () => {
  it('updates existing approvals and restores missing approvals without duplicates', () => {
    const existing = [{
      id: 'assistant-1',
      role: 'assistant' as const,
      text: 'approval requested',
      tools: [{ name: 'set_protection_level', sensitivity: 'modify', approval: approval('a-1', 'pending') }],
    }];
    const snapshot = [approval('a-1', 'executing'), approval('a-2', 'approved')];

    const restored = mergeRecoveredApprovals(existing, snapshot, [], t);
    const repeated = mergeRecoveredApprovals(restored, snapshot, [], t);

    expect(restored[0].tools?.[0].approval?.status).toBe('executing');
    expect(restored.flatMap((message) => message.tools ?? []).filter((tool) => tool.approval?.id === 'a-2')).toHaveLength(1);
    expect(repeated.flatMap((message) => message.tools ?? []).filter((tool) => tool.approval?.id === 'a-2')).toHaveLength(1);
  });
});
