import { useEffect, useMemo, useRef, useState } from 'react';
import { Button, Input, Message, Tag } from '@arco-design/web-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Bot, ChevronDown, ChevronUp, Send, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { approveAIApproval, askAIAssistantStream, executeAITool, fetchAITools, fetchLogs, fetchMonitorSummary, rejectAIApproval } from '../../api/client';
import type { AIAssistantTraceEvent, AIToolExecution } from '../../types/api';

type AssistantMessage = {
  id: string;
  role: 'user' | 'assistant' | 'tool';
  text: string;
  status?: string;
  createdAt?: string;
  meta?: AssistantMeta;
  process?: string[];
  processOpen?: boolean;
  tools?: AIToolExecution[];
  trace?: AIAssistantTraceEvent[];
};

type AssistantMeta = {
  thinkingMs: number;
  totalMs: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  tokenSpeed: number;
  events: number;
  blocked: number;
  challenge: number;
  provider?: string;
  model?: string;
};

export default function AIAssistant() {
  const { t, i18n } = useTranslation();
  const [open, setOpen] = useState(false);
  const [renderPanel, setRenderPanel] = useState(false);
  const [draft, setDraft] = useState('');
  const [thread, setThread] = useState<AssistantMessage[]>([]);
  const [pendingElapsedMs, setPendingElapsedMs] = useState(0);
  const [thinkingProcessOpen, setThinkingProcessOpen] = useState(true);
  const [pendingTrace, setPendingTrace] = useState<AIAssistantTraceEvent[]>([]);
  const pendingRef = useRef<{ startedAt: number; createdAt: string; inputTokens: number } | null>(null);
  const pendingTraceRef = useRef<AIAssistantTraceEvent[]>([]);
  const threadRef = useRef<HTMLDivElement | null>(null);
  const closeTimerRef = useRef<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const { data: tools } = useQuery({ queryKey: ['assistant-tools'], queryFn: fetchAITools, retry: false });
  const { data: monitor } = useQuery({ queryKey: ['assistant-monitor'], queryFn: fetchMonitorSummary, refetchInterval: 10_000, retry: false });
  const { data: logs } = useQuery({ queryKey: ['assistant-logs'], queryFn: () => fetchLogs({ limit: 5 }), refetchInterval: 10_000, retry: false });
  const liveContext = useMemo(() => {
    const snapshot = monitor?.snapshot;
    const events = (logs?.items ?? []).filter((entry) => entry.category || ['block', 'challenge', 'log'].includes(entry.action));
    return {
      requests: snapshot?.requests ?? 0,
      blocked: snapshot?.blocked ?? 0,
      latest: events[0],
      events: events.length,
    };
  }, [logs?.items, monitor?.snapshot]);

  const askMutation = useMutation({
    mutationFn: (message: string) => {
      const controller = new AbortController();
      abortRef.current = controller;
      return askAIAssistantStream(message, 30, i18n.language, (event) => {
        setPendingTrace((current) => {
          const next = [...current, event];
          pendingTraceRef.current = next;
          return next;
        });
      }, controller.signal);
    },
    onSuccess: (reply) => {
      const pending = pendingRef.current;
      const totalMs = pending ? performance.now() - pending.startedAt : 0;
      const outputTokens = reply.output_tokens || estimateTokens(reply.answer);
      const trace = reply.trace?.length ? reply.trace : pendingTraceRef.current;
      setThread((current) => [
        ...current,
        {
          id: `assistant-${Date.now()}`,
          role: 'assistant',
          text: reply.answer,
          status: reply.ai_used ? 'AI' : t('ai.heuristicUsed'),
          createdAt: new Date().toISOString(),
          meta: {
            thinkingMs: totalMs,
            totalMs,
            inputTokens: reply.input_tokens ?? 0,
            outputTokens,
            totalTokens: reply.total_tokens || outputTokens,
            tokenSpeed: tokensPerSecond(outputTokens, totalMs),
            events: reply.events,
            blocked: reply.blocked,
            challenge: reply.challenge,
            provider: reply.provider,
            model: reply.model,
          },
          process: [
            ...buildTraceProcess(t, trace),
            ...buildToolProcessSummary(t, reply.tool_executions ?? []),
          ],
          processOpen: false,
          trace,
          tools: reply.tool_executions,
        },
      ]);
      pendingRef.current = null;
      pendingTraceRef.current = [];
      setPendingTrace([]);
      abortRef.current = null;
    },
    onError: (error) => {
      const pending = pendingRef.current;
      const totalMs = pending ? performance.now() - pending.startedAt : 0;
      setThread((current) => [
        ...current,
        {
          id: `assistant-error-${Date.now()}`,
          role: 'assistant',
          text: error.message,
          status: 'error',
          createdAt: new Date().toISOString(),
          meta: {
            thinkingMs: totalMs,
            totalMs,
            inputTokens: 0,
            outputTokens: 0,
            totalTokens: 0,
            tokenSpeed: 0,
            events: liveContext.events,
            blocked: liveContext.blocked,
            challenge: 0,
          },
          process: [...buildTraceProcess(t, pendingTraceRef.current), t('assistant.processError')],
          processOpen: true,
          trace: pendingTraceRef.current,
        },
      ]);
      pendingRef.current = null;
      pendingTraceRef.current = [];
      setPendingTrace([]);
      abortRef.current = null;
    },
  });
  const approveToolMutation = useMutation({
    mutationFn: async (execution: AIToolExecution) => {
      if (!execution.approval?.id) {
        throw new Error(t('assistant.missingApproval'));
      }
      await approveAIApproval(execution.approval.id);
      return executeAITool(execution.name, execution.args ?? {}, execution.approval.id);
    },
    onSuccess: (result, execution) => {
      Message.success(t('assistant.toolExecuted'));
      const approvalID = execution.approval?.id;
      setThread((current) => [
        ...markApprovalStatus(current, approvalID, 'executed'),
        {
          id: `tool-${Date.now()}`,
          role: 'tool',
          text: t('assistant.toolExecutionCompleted', { tool: toolDisplayName(t, result.name) }),
          status: result.result?.success ? t('assistant.toolExecuted') : 'error',
          createdAt: new Date().toISOString(),
          tools: [result],
        },
      ]);
    },
    onError: (error) => Message.error(error.message),
  });
  const rejectToolMutation = useMutation({
    mutationFn: async (execution: AIToolExecution) => {
      if (!execution.approval?.id) {
        throw new Error(t('assistant.missingApproval'));
      }
      return rejectAIApproval(execution.approval.id);
    },
    onSuccess: (approval) => {
      Message.info(t('assistant.approvalRejected'));
      setThread((current) => [
        ...markApprovalStatus(current, approval.id, 'rejected'),
        {
          id: `tool-reject-${Date.now()}`,
          role: 'tool',
          text: t('assistant.approvalRejectedFor', { tool: approval.tool_name }),
          status: t('assistant.rejected'),
          createdAt: new Date().toISOString(),
        },
      ]);
    },
    onError: (error) => Message.error(error.message),
  });

  function clearCloseTimer() {
    if (closeTimerRef.current !== null) {
      window.clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
  }

  function openAssistant() {
    clearCloseTimer();
    setRenderPanel(true);
    setOpen(true);
  }

  function closeAssistant() {
    clearCloseTimer();
    setOpen(false);
    closeTimerRef.current = window.setTimeout(() => {
      setRenderPanel(false);
      closeTimerRef.current = null;
    }, 180);
  }

  function toggleAssistant() {
    if (open) {
      closeAssistant();
      return;
    }
    openAssistant();
  }

  useEffect(() => () => {
    clearCloseTimer();
    abortRef.current?.abort();
  }, []);

  useEffect(() => {
    if (!askMutation.isPending) {
      setPendingElapsedMs(0);
      setThinkingProcessOpen(true);
      return undefined;
    }
    const timer = window.setInterval(() => {
      const pending = pendingRef.current;
      if (pending) {
        setPendingElapsedMs(performance.now() - pending.startedAt);
      }
    }, 250);
    return () => window.clearInterval(timer);
  }, [askMutation.isPending]);

  const messages: AssistantMessage[] = [
    ...thread,
    ...(askMutation.isPending ? [{
      id: 'thinking',
      role: 'assistant' as const,
      text: pendingTrace[pendingTrace.length - 1]?.message || t('assistant.thinking'),
      status: t('assistant.working'),
      createdAt: pendingRef.current?.createdAt,
      meta: {
        thinkingMs: pendingElapsedMs,
        totalMs: pendingElapsedMs,
        inputTokens: pendingRef.current?.inputTokens ?? 0,
        outputTokens: 0,
        totalTokens: pendingRef.current?.inputTokens ?? 0,
        tokenSpeed: 0,
        events: liveContext.events,
        blocked: liveContext.blocked,
        challenge: 0,
      },
      process: buildTraceProcess(t, pendingTrace),
      processOpen: thinkingProcessOpen,
      trace: pendingTrace,
    }] : []),
  ];

  useEffect(() => {
    if (!open || !threadRef.current) {
      return;
    }
    const frame = window.requestAnimationFrame(() => {
      threadRef.current?.scrollTo({ top: threadRef.current.scrollHeight, behavior: 'auto' });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [open, messages.length, askMutation.isPending]);

  function submit() {
    const message = draft.trim();
    if (!message) {
      return;
    }
    setDraft('');
    setPendingElapsedMs(0);
    setThinkingProcessOpen(true);
    pendingTraceRef.current = [];
    setPendingTrace([]);
    pendingRef.current = { startedAt: performance.now(), createdAt: new Date().toISOString(), inputTokens: estimateTokens(message) };
    setThread((current) => [...current, { id: `user-${Date.now()}`, role: 'user', text: message, createdAt: new Date().toISOString() }]);
    askMutation.mutate(message);
  }

  function toggleProcess(messageID: string) {
    if (messageID === 'thinking') {
      setThinkingProcessOpen((value) => !value);
      return;
    }
    setThread((current) => current.map((message) => (
      message.id === messageID ? { ...message, processOpen: !message.processOpen } : message
    )));
  }

  return (
    <>
      <Button
        aria-label={t('assistant.title')}
        className={[
          'ai-fab',
          open ? 'ai-fab-open' : '',
          askMutation.isPending ? 'ai-fab-working' : '',
        ].filter(Boolean).join(' ')}
        type="primary"
        shape="circle"
        icon={<Bot size={36} strokeWidth={1.8} />}
        onClick={toggleAssistant}
      />
      {renderPanel && (
        <section
          className={open ? 'ai-assistant-panel' : 'ai-assistant-panel ai-assistant-panel-closing'}
          onAnimationEnd={() => {
            if (!open) {
              clearCloseTimer();
              setRenderPanel(false);
            }
          }}
        >
          <header>
            <strong>{t('assistant.title')}</strong>
            {tools?.length ? <Tag>{t('assistant.toolsAvailable', { count: tools.length })}</Tag> : null}
            <button
              className="assistant-close-button"
              type="button"
              aria-label={t('common.close')}
              onPointerDown={(event) => event.stopPropagation()}
              onClick={(event) => {
                event.preventDefault();
                event.stopPropagation();
                closeAssistant();
              }}
            >
              <X size={16} />
            </button>
          </header>
          <div className="assistant-thread" ref={threadRef} aria-live="polite">
            {messages.map((message) => (
              <div
                key={message.id}
                className={[
                  'assistant-message',
                  `assistant-${message.role}`,
                  message.id === 'thinking' ? 'assistant-thinking' : '',
                ].filter(Boolean).join(' ')}
              >
                <span>{message.text}</span>
                {message.id === 'thinking' && (
                  <span className="assistant-dots" aria-hidden="true">
                    <i />
                    <i />
                    <i />
                  </span>
                )}
                {message.status && <Tag>{message.status}</Tag>}
                {message.meta && (
                  <div className="assistant-meta">
                    {message.meta.provider && <span>{message.meta.model ? `${message.meta.provider} / ${message.meta.model}` : message.meta.provider}</span>}
                    <span>{t('assistant.thinkingDuration', { value: formatDuration(message.meta.thinkingMs) })}</span>
                    <span>{t('assistant.totalDuration', { value: formatDuration(message.meta.totalMs) })}</span>
                    <span>{t('assistant.outputTokens', { value: message.meta.outputTokens })}</span>
                    <span>{t('assistant.tokenSpeed', { value: formatTokenSpeed(message.meta.tokenSpeed) })}</span>
                    <span>{formatMessageTime(message.createdAt)}</span>
                  </div>
                )}
                {message.process && message.process.length > 0 && (
                  <div className="assistant-process">
                    <button type="button" onClick={() => toggleProcess(message.id)}>
                      {message.processOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                      <span>{message.processOpen ? t('assistant.hideProcess') : t('assistant.showProcess')}</span>
                    </button>
                    {message.processOpen && (
                      <ol>
                        {message.process.map((item) => <li key={item}>{item}</li>)}
                      </ol>
                    )}
                  </div>
                )}
                {message.tools && message.tools.length > 0 && (
                  <div className="assistant-tools">
                    {message.tools.map((tool) => {
                      const toolName = toolDisplayName(t, tool.name);
                      const sensitivity = sensitivityDisplayName(t, tool.sensitivity);
                      const approvalStatus = tool.approval?.status;
                      const status = approvalStatus ? approvalStatusDisplayName(t, approvalStatus) : undefined;
                      const description = toolDescription(t, tool);
                      return (
                        <div className="assistant-tool-card" key={`${tool.name}-${tool.approval?.id ?? tool.result?.output ?? tool.error ?? 'tool'}`}>
                          <div className="assistant-tool-card-head">
                            <div className="assistant-tool-title">
                              <strong>{toolName}</strong>
                              <span>{t('assistant.toolId', { id: tool.name })}</span>
                            </div>
                            <div className="assistant-tool-badges">
                              {status && (
                                <span className={`assistant-tool-badge assistant-tool-status-${cssToken(approvalStatus)}`}>
                                  {status}
                                </span>
                              )}
                              <span className={`assistant-tool-badge assistant-tool-sensitivity-${cssToken(tool.sensitivity)}`}>
                                {sensitivity}
                              </span>
                            </div>
                          </div>
                          {description && <p>{description}</p>}
                          {tool.result && (
                            <div className={tool.result.success ? 'assistant-tool-result' : 'assistant-tool-result assistant-tool-result-error'}>
                              <span>{tool.result.success ? t('assistant.toolResult') : t('assistant.toolFailed')}</span>
                              {tool.result.output && (
                                <div className="assistant-tool-section">
                                  <small>{t('assistant.resultOutput')}</small>
                                  <pre>{tool.result.output}</pre>
                                </div>
                              )}
                              {tool.result.diff && (
                                <div className="assistant-tool-section assistant-tool-section-diff">
                                  <small>{t('assistant.diffPreview')}</small>
                                  <pre>{tool.result.diff}</pre>
                                </div>
                              )}
                              {tool.result.error && (
                                <div className="assistant-tool-section">
                                  <small>{t('assistant.errorDetail')}</small>
                                  <pre>{tool.result.error}</pre>
                                </div>
                              )}
                            </div>
                          )}
                          {tool.error && !tool.result && (
                            <div className="assistant-tool-result assistant-tool-result-error">
                              <div className="assistant-tool-section">
                                <small>{t('assistant.errorDetail')}</small>
                                <pre>{tool.error}</pre>
                              </div>
                            </div>
                          )}
                          {tool.approval && tool.approval.status !== 'pending' && (
                            <div className={`assistant-approval-state assistant-approval-state-${cssToken(tool.approval.status)}`}>
                              <span>{approvalStatusDisplayName(t, tool.approval.status)}</span>
                              <small>{t('assistant.approvalCompleted', { tool: toolName })}</small>
                            </div>
                          )}
                          {tool.approval && tool.approval.status === 'pending' && (
                            <div className="assistant-approval">
                              <div className="assistant-approval-head">
                                <strong>{t('assistant.approvalRequired')}</strong>
                                <span>{t('assistant.approvalTool', { tool: toolName })}</span>
                              </div>
                              {tool.approval.diff && (
                                <div className="assistant-tool-section assistant-tool-section-diff">
                                  <small>{t('assistant.diffPreview')}</small>
                                  <pre>{tool.approval.diff}</pre>
                                </div>
                              )}
                              <div className="assistant-approval-actions">
                                <Button
                                  size="small"
                                  type="primary"
                                  loading={approveToolMutation.isPending}
                                  onClick={() => approveToolMutation.mutate(tool)}
                                >
                                  {t('assistant.approve')}
                                </Button>
                                <Button
                                  size="small"
                                  status="warning"
                                  loading={rejectToolMutation.isPending}
                                  onClick={() => rejectToolMutation.mutate(tool)}
                                >
                                  {t('assistant.reject')}
                                </Button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            ))}
          </div>
          <div className="assistant-input">
            <Input
              value={draft}
              placeholder={t('assistant.placeholder')}
              onChange={setDraft}
              onPressEnter={submit}
            />
            <Button type="primary" icon={<Send size={14} />} loading={askMutation.isPending} onClick={submit} />
          </div>
        </section>
      )}
    </>
  );
}

function markApprovalStatus(messages: AssistantMessage[], approvalID: string | undefined, status: string) {
  if (!approvalID) {
    return messages;
  }
  return messages.map((message) => {
    if (!message.tools) {
      return message;
    }
    return {
      ...message,
      tools: message.tools.map((tool) => (
        tool.approval?.id === approvalID
          ? { ...tool, approval: { ...tool.approval, status } }
          : tool
      )),
    };
  });
}

function toolDisplayName(t: (key: string, options?: Record<string, unknown>) => string, name: string) {
  return t(`assistant.toolNames.${name}`, { defaultValue: name });
}

function toolDescription(t: (key: string, options?: Record<string, unknown>) => string, tool: AIToolExecution) {
  return t(`assistant.toolDescriptions.${tool.name}`, { defaultValue: tool.description ?? '' });
}

function sensitivityDisplayName(t: (key: string, options?: Record<string, unknown>) => string, value: string) {
  return t(`assistant.sensitivity.${value}`, { defaultValue: value });
}

function approvalStatusDisplayName(t: (key: string, options?: Record<string, unknown>) => string, value: string) {
  return t(`assistant.approvalStatus.${value}`, { defaultValue: value });
}

function cssToken(value?: string) {
  return (value || 'unknown').toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
}

function buildToolProcessSummary(
  t: (key: string, options?: Record<string, unknown>) => string,
  tools: AIToolExecution[],
) {
  if (tools.length === 0) {
    return [];
  }
  const readOnly = tools.filter((tool) => tool.sensitivity === 'read_only' && tool.result?.success).length;
  const approvals = tools.filter((tool) => tool.approval?.status === 'pending').length;
  const executed = tools.filter((tool) => tool.sensitivity !== 'read_only' && tool.result?.success).length;
  return [t('assistant.processTools', { readOnly, approvals, executed })];
}

function buildTraceProcess(t: (key: string, options?: Record<string, unknown>) => string, trace: AIAssistantTraceEvent[]) {
  if (trace.length === 0) {
    return [t('assistant.traceWaiting')];
  }
  return trace.map((event) => formatTraceEvent(t, event));
}

function formatTraceEvent(t: (key: string, options?: Record<string, unknown>) => string, event: AIAssistantTraceEvent) {
  switch (event.type) {
    case 'tool_call':
      return t('assistant.traceToolCall', { tool: event.tool_name || '-', args: compactJson(event.args) });
    case 'tool_result':
      return t('assistant.traceToolResult', { tool: event.tool_name || '-', output: summarizeOutput(event.result?.output) });
    case 'approval_required':
      return t('assistant.traceApproval', { tool: event.tool_name || '-' });
    case 'tool_error':
    case 'planning_error':
    case 'final_error':
      return t('assistant.traceError', { step: event.tool_name || event.type, error: event.error || event.message });
    default:
      return event.message || event.type;
  }
}

function compactJson(value: unknown) {
  if (!value || (typeof value === 'object' && Object.keys(value as Record<string, unknown>).length === 0)) {
    return '{}';
  }
  try {
    const text = JSON.stringify(value);
    return text.length > 120 ? `${text.slice(0, 117)}...` : text;
  } catch {
    return String(value);
  }
}

function summarizeOutput(value?: string) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  if (!text) {
    return '-';
  }
  return text.length > 160 ? `${text.slice(0, 157)}...` : text;
}

function estimateTokens(text: string) {
  const trimmed = text.trim();
  if (!trimmed) {
    return 0;
  }
  const latinWords = trimmed.match(/[A-Za-z0-9_'-]+/g)?.length ?? 0;
  const cjkChars = trimmed.match(/[\u3400-\u9fff]/g)?.length ?? 0;
  return Math.max(1, Math.ceil(latinWords * 1.25 + cjkChars * 0.85));
}

function tokensPerSecond(tokens: number, durationMs: number) {
  if (tokens <= 0 || durationMs <= 0) {
    return 0;
  }
  return tokens / (durationMs / 1000);
}

function formatDuration(ms: number) {
  if (!Number.isFinite(ms) || ms <= 0) {
    return '0.0s';
  }
  return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)}s`;
}

function formatTokenSpeed(value: number) {
  if (!Number.isFinite(value) || value <= 0) {
    return '0 tok/s';
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} tok/s`;
}

function formatMessageTime(value?: string) {
  if (!value) {
    return '';
  }
  return new Date(value).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
