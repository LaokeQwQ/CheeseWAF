import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AIConfig, AIModelConfig } from '../../types/api';
import AIPage, { buildAIConfigPayload, validateSelfLearningMaxEvents } from './AIPage';

const apiMocks = vi.hoisted(() => ({
  fetchAIConfig: vi.fn(),
  fetchLogs: vi.fn(),
  updateAIConfig: vi.fn(),
  fetchAIModels: vi.fn(),
  testAIConnection: vi.fn(),
  runAISelfLearning: vi.fn(),
  analyzeLogReferenceStream: vi.fn(),
  analyzeEventsStream: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
    i18n: { language: 'en-US' },
  }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return {
    ...actual,
    fetchAIConfig: apiMocks.fetchAIConfig,
    fetchLogs: apiMocks.fetchLogs,
    updateAIConfig: apiMocks.updateAIConfig,
    fetchAIModels: apiMocks.fetchAIModels,
    testAIConnection: apiMocks.testAIConnection,
    runAISelfLearning: apiMocks.runAISelfLearning,
    analyzeLogReferenceStream: apiMocks.analyzeLogReferenceStream,
    analyzeEventsStream: apiMocks.analyzeEventsStream,
  };
});

const baseModel: AIModelConfig = {
  provider: 'openai',
  api_base: 'https://api.openai.com/v1',
  api_key: '',
  api_key_set: true,
  model: 'gpt-4o-mini',
  allow_private_api_base: false,
};

const baseConfig: AIConfig = {
  enabled: true,
  provider: 'openai',
  api_base: 'https://api.openai.com/v1',
  api_key: '',
  api_key_set: true,
  model: 'gpt-4o-mini',
  async: true,
  allow_private_api_base: false,
  assistant: baseModel,
  reasoning: baseModel,
  self_learning: {
    enabled: true,
    auto_apply: false,
    dry_run: true,
    interval: '24h',
    at: '03:30',
    min_confidence: 0.995,
    min_events: 5,
    max_events: 321,
    max_rules_per_run: 3,
    action: 'block',
  },
  knowledge: {
    enabled: true,
    builtin: true,
    max_snippets: 5,
  },
};

describe('AI self-learning max_events', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMocks.fetchAIConfig.mockResolvedValue(baseConfig);
    apiMocks.fetchLogs.mockResolvedValue({ items: [] });
  });

  it('renders max_events from the loaded config in an editable number input', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });

    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <AIPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await waitFor(() => expect(apiMocks.fetchAIConfig).toHaveBeenCalled());
    expect(await screen.findByDisplayValue('321')).toBeTruthy();
  });

  it('saves a validated numeric max_events value into the API payload', () => {
    const payload = buildAIConfigPayload({
      enabled: true,
      assistantProvider: 'openai',
      assistantAPIBase: 'https://api.openai.com/v1',
      assistantAPIKey: '',
      assistantModel: 'gpt-4o-mini',
      assistantAllowPrivateAPIBase: false,
      reasoningProvider: 'openai',
      reasoningAPIBase: 'https://api.openai.com/v1',
      reasoningAPIKey: '',
      reasoningModel: 'gpt-4o-mini',
      reasoningAllowPrivateAPIBase: false,
      async: true,
      selfLearningEnabled: true,
      selfLearningAutoApply: false,
      selfLearningDryRun: true,
      selfLearningInterval: '24h',
      selfLearningAt: '03:30',
      selfLearningMinConfidence: 0.995,
      selfLearningMinEvents: 5,
      selfLearningMaxEvents: '512',
      selfLearningMaxRulesPerRun: 3,
      selfLearningAction: 'block',
      knowledgeEnabled: true,
      knowledgeBuiltin: true,
      knowledgeMaxSnippets: 5,
    }, baseConfig, baseModel, baseModel);

    expect(payload.self_learning?.max_events).toBe(512);
  });

  it('rejects max_events outside the allowed integer range', () => {
    expect(() => validateSelfLearningMaxEvents(0)).toThrow('self_learning.max_events');
    expect(() => validateSelfLearningMaxEvents(10_001)).toThrow('self_learning.max_events');
    expect(() => validateSelfLearningMaxEvents(42.5)).toThrow('self_learning.max_events');
  });
});
