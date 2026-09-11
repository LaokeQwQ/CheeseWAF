import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
  fetchAIOpsUsage: vi.fn(),
  fetchAIOpsProviders: vi.fn(),
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
    fetchAIOpsUsage: apiMocks.fetchAIOpsUsage,
    fetchAIOpsProviders: apiMocks.fetchAIOpsProviders,
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
    apiMocks.fetchAIOpsUsage.mockResolvedValue({
      range: { start: '2026-09-03T12:00:00Z', end: '2026-09-10T12:00:00Z' },
      input_tokens: 1200,
      output_tokens: 800,
      total_tokens: 2000,
      call_count: 7,
      input_tokens_formatted: '1.20K',
      output_tokens_formatted: '800',
      total_tokens_formatted: '2.00K',
      by_provider: { openai: { input_tokens: 1200, output_tokens: 800, total_tokens: 2000, call_count: 7 } },
      by_model: { 'gpt-4o-mini': { input_tokens: 1200, output_tokens: 800, total_tokens: 2000, call_count: 7 } },
    });
    apiMocks.fetchAIOpsProviders.mockResolvedValue({
      items: [{
        target: 'assistant',
        provider: 'openai',
        status: 'ready',
        display_model_name: 'Assistant Visible',
        invocation_model_name: 'assistant-invoke',
        context_window: 131072,
        reasoning_effort: 'medium',
        balance_configured: true,
        usage_configured: true,
        balance: { available: 12.5, used: 2.5, limit: 15, currency: 'USD' },
      }],
      total: 1,
    });
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

  it('preserves dirty form values across config refetch', async () => {
    apiMocks.fetchAIConfig.mockReset();
    apiMocks.fetchAIConfig
      .mockResolvedValueOnce(baseConfig)
      .mockResolvedValueOnce({
        ...baseConfig,
        self_learning: { ...baseConfig.self_learning, max_events: 999 },
      });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });

    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <AIPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    const input = await screen.findByDisplayValue('321');
    fireEvent.change(input, { target: { value: '777' } });
    expect(screen.getByDisplayValue('777')).toBeTruthy();

    await client.invalidateQueries({ queryKey: ['ai-config'] });
    await waitFor(() => expect(apiMocks.fetchAIConfig).toHaveBeenCalledTimes(2));
    expect(screen.getByDisplayValue('777')).toBeTruthy();
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

  it('preserves provider paths and separate display/invocation model metadata in the save payload', () => {
    const payload = buildAIConfigPayload({
      enabled: true,
      assistantProvider: 'openai',
      assistantAPIBase: 'https://gateway.example/v1',
      assistantAPIKey: '',
      assistantModel: 'assistant-invoke',
      assistantDisplayModelName: 'Assistant Visible',
      assistantContextWindow: '131072',
      assistantReasoningEffort: 'medium',
      assistantModelListPath: 'models',
      assistantBalancePath: 'account/balance',
      assistantUsagePath: 'account/usage',
      assistantAllowPrivateAPIBase: false,
      reasoningProvider: 'openai',
      reasoningAPIBase: 'https://gateway.example/v1',
      reasoningAPIKey: '',
      reasoningModel: 'reasoning-invoke',
      reasoningDisplayModelName: 'Reasoning Visible',
      reasoningContextWindow: '200000',
      reasoningReasoningEffort: 'high',
      reasoningModelListPath: 'models',
      reasoningBalancePath: 'account/balance',
      reasoningUsagePath: 'account/usage',
      reasoningAllowPrivateAPIBase: false,
      async: true,
      selfLearningEnabled: false,
      selfLearningAutoApply: false,
      selfLearningDryRun: true,
      selfLearningInterval: '24h',
      selfLearningAt: '03:30',
      selfLearningMinConfidence: 0.995,
      selfLearningMinEvents: 5,
      selfLearningMaxEvents: '200',
      selfLearningMaxRulesPerRun: 3,
      selfLearningAction: 'block',
      knowledgeEnabled: true,
      knowledgeBuiltin: true,
      knowledgeMaxSnippets: 5,
    }, baseConfig, baseModel, baseModel);

    expect(payload.assistant).toMatchObject({
      model: 'assistant-invoke',
      invocation_model_name: 'assistant-invoke',
      display_model_name: 'Assistant Visible',
      context_window: 131072,
      reasoning_effort: 'medium',
      model_list_path: 'models',
      balance_path: 'account/balance',
      usage_path: 'account/usage',
    });
    expect(payload.reasoning).toMatchObject({
      invocation_model_name: 'reasoning-invoke',
      display_model_name: 'Reasoning Visible',
      context_window: 200000,
      reasoning_effort: 'high',
    });
  });

  it('rejects max_events outside the allowed integer range', () => {
    expect(() => validateSelfLearningMaxEvents(0)).toThrow(/max_events must be/);
    expect(() => validateSelfLearningMaxEvents(10_001)).toThrow(/max_events must be/);
    expect(() => validateSelfLearningMaxEvents(42.5)).toThrow(/max_events must be/);
  });

  it('renders AI Ops usage and provider balance with preset and custom UTC ranges', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <AIPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(await screen.findByText('2.00K')).toBeTruthy();
    expect(screen.getByText('7')).toBeTruthy();
    expect(screen.getByText('Assistant Visible')).toBeTruthy();
    expect(screen.getByText('USD 12.50')).toBeTruthy();
    expect(apiMocks.fetchAIOpsUsage).toHaveBeenCalledWith({ range: '7d' });

    fireEvent.click(screen.getByRole('button', { name: 'ai.opsRange30d' }));
    await waitFor(() => expect(apiMocks.fetchAIOpsUsage).toHaveBeenCalledWith({ range: '30d' }));

    fireEvent.click(screen.getByRole('button', { name: 'ai.opsRangeCustom' }));
    fireEvent.change(screen.getByLabelText('ai.opsCustomStart'), { target: { value: '2026-09-01T00:00' } });
    fireEvent.change(screen.getByLabelText('ai.opsCustomEnd'), { target: { value: '2026-09-10T12:00' } });
    fireEvent.click(screen.getByRole('button', { name: 'ai.opsApplyRange' }));
    await waitFor(() => expect(apiMocks.fetchAIOpsUsage).toHaveBeenCalledWith({
      range: 'custom',
      start: '2026-09-01T00:00:00.000Z',
      end: '2026-09-10T12:00:00.000Z',
    }));
  });
});
