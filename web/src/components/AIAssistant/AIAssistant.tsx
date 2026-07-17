import { useEffect, useMemo, useRef, useState } from 'react';
import { Button, Input, Message, Switch, Tag } from '@arco-design/web-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Bot, ChevronDown, ChevronUp, Send, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { APIRequestError, approveAIApproval, askAIAssistantStream, continueAIApprovalStream, fetchAIApprovals, fetchAITools, rejectAIApproval } from '../../api/client';
import type { AIApprovalRequest, AIAssistantReply, AIAssistantTraceEvent, AIToolExecution } from '../../types/api';
import { useAppStore } from '../../stores';
import SafeMarkdown, { safeAssistantDisplayText } from '../SafeMarkdown';
import AIAssistantFab from './AIAssistantFab';
import './AIAssistant.css';

type AssistantMessage = {
  id: string;
  role: 'user' | 'assistant' | 'tool';
  text: string;
  status?: string;
  createdAt?: string;
  meta?: AssistantMeta;
  process?: string[];
  processOpen?: boolean;
  traceOpen?: boolean;
  tools?: AIToolExecution[];
  trace?: AIAssistantTraceEvent[];
  prompt?: string;
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

type ApprovalContinuationInput = {
  execution: AIToolExecution;
  prompt: string;
};

type AIAssistantProps = {
  initialOpen?: boolean;
};

export default function AIAssistant({ initialOpen = false }: AIAssistantProps) {
  const { t, i18n } = useTranslation();
  const fabVisible = useAppStore((state) => state.aiAssistantFabVisible);
  const [open, setOpen] = useState(initialOpen);
  const [renderPanel, setRenderPanel] = useState(initialOpen);
  const [draft, setDraft] = useState('');
  const [thread, setThread] = useState<AssistantMessage[]>([]);
  const [pendingElapsedMs, setPendingElapsedMs] = useState(0);
  const [thinkingProcessOpen, setThinkingProcessOpen] = useState(true);
  const [pendingTraceOpen, setPendingTraceOpen] = useState(true);
  const [pendingTrace, setPendingTrace] = useState<AIAssistantTraceEvent[]>([]);
  const [pendingContent, setPendingContent] = useState('');
  const [deepThink, setDeepThink] = useState(false);
  const [continuingApprovalID, setContinuingApprovalID] = useState<string | null>(null);
  const pendingRef = useRef<{ startedAt: number; createdAt: string; inputTokens: number; prompt?: string; providerStartedAt?: number } | null>(null);
  const pendingTraceRef = useRef<AIAssistantTraceEvent[]>([]);
  const pendingContentRef = useRef('');
  const threadRef = useRef<HTMLDivElement | null>(null);
  const closeTimerRef = useRef<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const forceScrollRef = useRef(false);
  const assistantActive = open || renderPanel;
  const { data: tools } = useQuery({ queryKey: ['assistant-tools'], queryFn: fetchAITools, enabled: assistantActive, retry: false });
  const hasActiveApprovals = useMemo(
    () => thread.some((message) => message.tools?.some((tool) => {
      const status = tool.approval?.status;
      return status === 'pending' || status === 'approved' || status === 'executing';
    })),
    [thread],
  );
  const { data: recoverableApprovals, refetch: refetchApprovals } = useQuery({
    queryKey: ['assistant-approvals'],
    queryFn: () => fetchAIApprovals(),
    enabled: assistantActive,
    retry: false,
    // Poll only while an approval is in-flight; otherwise refresh on open only.
    refetchInterval: assistantActive && hasActiveApprovals ? 5_000 : false,
  });
  const liveContext = useMemo(() => ({
    requests: 0,
    blocked: 0,
    latest: undefined as undefined,
    events: 0,
  }), []);

  const recordPendingTrace = (event: AIAssistantTraceEvent) => {
    if (isProviderFirstTraceEvent(event.type) && pendingRef.current && !pendingRef.current.providerStartedAt) {
      pendingRef.current = { ...pendingRef.current, providerStartedAt: performance.now() };
    }
    if (event.approval?.id && event.approval.status) {
      setThread((current) => markApprovalStatus(current, event.approval?.id, event.approval?.status || 'pending', { preserveProgress: true }));
    }
    if (event.type === 'content_delta') {
      pendingContentRef.current += event.message ?? '';
      setPendingContent(pendingContentRef.current);
    }
    const next = [...pendingTraceRef.current, event];
    pendingTraceRef.current = next;
    setPendingTrace(next);
  };

  function clearPendingState() {
    pendingRef.current = null;
    pendingTraceRef.current = [];
    pendingContentRef.current = '';
    setPendingTrace([]);
    setPendingContent('');
    abortRef.current = null;
  }

  function appendAssistantReply(reply: AIAssistantReply, options: { approvalID?: string } = {}) {
    const pending = pendingRef.current;
    const totalMs = pending ? performance.now() - pending.startedAt : 0;
    const thinkingMs = pending?.providerStartedAt ? pending.providerStartedAt - pending.startedAt : totalMs;
    const outputTokens = reply.output_tokens || estimateTokens(reply.answer);
    const trace = reply.trace?.length ? reply.trace : pendingTraceRef.current;
    setThread((current) => {
      const base = options.approvalID ? markApprovalStatus(current, options.approvalID, 'executed') : current;
      return [
        ...base,
        {
          id: `assistant-${Date.now()}`,
          role: 'assistant',
          text: reply.answer,
          status: reply.ai_used ? 'AI' : t('ai.heuristicUsed'),
          createdAt: new Date().toISOString(),
          prompt: pending?.prompt,
          meta: {
            thinkingMs,
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
          process: buildReasoningProcess(t, reply.reasoning_summary, reply.ai_used),
          processOpen: true,
          traceOpen: false,
          trace,
          tools: reply.tool_executions,
        },
      ];
    });
    clearPendingState();
  }

  function appendAssistantError(error: Error) {
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
        prompt: pending?.prompt,
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
        process: [t('assistant.processError')],
        processOpen: true,
        traceOpen: false,
        trace: pendingTraceRef.current,
      },
    ]);
    clearPendingState();
  }

  const askMutation = useMutation({
    mutationFn: (message: string) => {
      const controller = new AbortController();
      abortRef.current = controller;
      return askAIAssistantStream(message, 30, i18n.language, deepThink, recordPendingTrace, controller.signal);
    },
    onSuccess: (reply) => appendAssistantReply(reply),
    onError: (error) => appendAssistantError(error),
  });
  const continueApprovalMutation = useMutation({
    mutationFn: async ({ execution, prompt }: ApprovalContinuationInput) => {
      if (!execution.approval?.id) {
        throw new Error(t('assistant.missingApproval'));
      }
      const controller = new AbortController();
      abortRef.current = controller;
      return continueAIApprovalStream(execution.approval.id, prompt, 30, i18n.language, deepThink, recordPendingTrace, controller.signal);
    },
    onSuccess: (reply, { execution }) => {
      Message.success(t('assistant.toolExecuted'));
      appendAssistantReply(reply, { approvalID: execution.approval?.id });
      setContinuingApprovalID(null);
      void refetchApprovals();
    },
    onError: (error, { execution }) => {
      const reconciled = error instanceof APIRequestError ? error.approval : undefined;
      if (reconciled) {
        setThread((current) => markApprovalStatus(current, reconciled.id, reconciled.status));
        if (reconciled.status === 'failed') {
          Message.error(reconciled.error || error.message);
        } else if (reconciled.status === 'executing') {
          Message.info(t('assistant.approvalStatus.executing', { defaultValue: 'Execution continues on the server' }));
        } else if (reconciled.status === 'executed') {
          Message.success(t('assistant.approvalStatus.executed', { defaultValue: 'Executed' }));
        } else {
          Message.warning(t('assistant.approvalStatus.pending', { defaultValue: 'Approval is waiting to continue' }));
        }
        clearPendingState();
      } else {
        // Roll back optimistic "executing" so Continue/Reject stay usable.
        if (execution.approval?.id) {
          setThread((current) => markApprovalStatus(current, execution.approval?.id, 'approved'));
        }
        Message.warning(error.message);
        appendAssistantError(error);
      }
      setContinuingApprovalID(null);
      void refetchApprovals();
    },
  });
  const approveToolMutation = useMutation({
    mutationFn: async (execution: AIToolExecution) => {
      if (!execution.approval?.id) {
        throw new Error(t('assistant.missingApproval'));
      }
      return approveAIApproval(execution.approval.id);
    },
    onSuccess: (approval) => {
      Message.success(t('assistant.approvalReady'));
      setThread((current) => markApprovalStatus(current, approval.id, approval.status));
      void refetchApprovals();
    },
    onError: (error) => {
      const forbidden = error instanceof APIRequestError && (error.status === 403 || error.code === 'AI_APPROVAL_FORBIDDEN');
      Message.error(forbidden ? t('assistant.needsAnotherApprover') : error.message);
    },
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
      void refetchApprovals();
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
    // Cancel in-flight streams when the panel closes to free the server and UI.
    abortRef.current?.abort();
    setOpen(false);
    const closeDelay = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 160;
    closeTimerRef.current = window.setTimeout(() => {
      setRenderPanel(false);
      closeTimerRef.current = null;
    }, closeDelay);
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
    const approvals = recoverableApprovals?.items ?? [];
    if (approvals.length === 0) {
      return;
    }
    setThread((current) => mergeRecoveredApprovals(current, approvals, tools ?? [], t));
  }, [recoverableApprovals?.items, t, tools]);

  const assistantBusy = askMutation.isPending || continueApprovalMutation.isPending;

  useEffect(() => {
    if (!assistantBusy) {
      setPendingElapsedMs(0);
      setThinkingProcessOpen(true);
      setPendingTraceOpen(true);
      return undefined;
    }
    const timer = window.setInterval(() => {
      const pending = pendingRef.current;
      if (pending) {
        setPendingElapsedMs(performance.now() - pending.startedAt);
      }
    }, 250);
    return () => window.clearInterval(timer);
  }, [assistantBusy]);

  const messages: AssistantMessage[] = [
    ...thread,
    ...(assistantBusy ? [{
      id: 'thinking',
      role: 'assistant' as const,
      text: pendingContent || pendingAssistantText(t, pendingTrace),
      status: t('assistant.working'),
      createdAt: pendingRef.current?.createdAt,
      meta: {
        thinkingMs: pendingRef.current?.providerStartedAt ? pendingRef.current.providerStartedAt - pendingRef.current.startedAt : pendingElapsedMs,
        totalMs: pendingElapsedMs,
        inputTokens: pendingRef.current?.inputTokens ?? 0,
        outputTokens: 0,
        totalTokens: pendingRef.current?.inputTokens ?? 0,
        tokenSpeed: 0,
        events: liveContext.events,
        blocked: liveContext.blocked,
        challenge: 0,
      },
      process: buildLiveReasoningProcess(t, pendingTrace),
      processOpen: thinkingProcessOpen,
      traceOpen: pendingTraceOpen,
      trace: pendingTrace,
    }] : []),
  ];

  useEffect(() => {
    if (!open || !threadRef.current) {
      return;
    }
    const thread = threadRef.current;
    const isAtBottom = thread.scrollHeight - (thread.scrollTop + thread.clientHeight) < 64;
    const shouldForce = forceScrollRef.current;
    if (!isAtBottom && !shouldForce) {
      return;
    }
    let secondFrame = 0;
    let fallbackTimer = 0;
    const scrollToLatest = () => {
      thread.scrollTo({ top: thread.scrollHeight, behavior: 'auto' });
      forceScrollRef.current = false;
    };
    const frame = window.requestAnimationFrame(() => {
      scrollToLatest();
      secondFrame = window.requestAnimationFrame(scrollToLatest);
      fallbackTimer = window.setTimeout(scrollToLatest, 80);
    });
    return () => {
      window.cancelAnimationFrame(frame);
      if (secondFrame) {
        window.cancelAnimationFrame(secondFrame);
      }
      if (fallbackTimer) {
        window.clearTimeout(fallbackTimer);
      }
    };
  }, [open, messages.length, assistantBusy, pendingContent, pendingTrace.length]);

  function submit() {
    sendMessage(draft);
  }

  function sendMessage(raw: string) {
    const message = raw.trim();
    if (!message || assistantBusy) {
      return;
    }
    setDraft('');
    setPendingElapsedMs(0);
    setThinkingProcessOpen(true);
    setPendingTraceOpen(true);
    pendingTraceRef.current = [];
    pendingContentRef.current = '';
    setPendingTrace([]);
    setPendingContent('');
    forceScrollRef.current = true;
    pendingRef.current = { startedAt: performance.now(), createdAt: new Date().toISOString(), inputTokens: estimateTokens(message), prompt: message };
    setThread((current) => [...current, { id: `user-${Date.now()}`, role: 'user', text: message, createdAt: new Date().toISOString(), prompt: message }]);
    askMutation.mutate(message);
  }

  function continueApproval(tool: AIToolExecution, prompt: string | undefined) {
    const approvalID = tool.approval?.id;
    if (!approvalID || assistantBusy || rejectToolMutation.isPending) {
      return;
    }
    const message = (prompt || lastUserPrompt(thread) || t('assistant.approvalContinueFallback', { tool: toolDisplayName(t, tool.name) })).trim();
    setPendingElapsedMs(0);
    setThinkingProcessOpen(true);
    setPendingTraceOpen(true);
    pendingTraceRef.current = [];
    pendingContentRef.current = '';
    setPendingTrace([]);
    setPendingContent('');
    forceScrollRef.current = true;
    pendingRef.current = { startedAt: performance.now(), createdAt: new Date().toISOString(), inputTokens: estimateTokens(message), prompt: message };
    setContinuingApprovalID(approvalID);
    setThread((current) => markApprovalStatus(current, approvalID, 'executing'));
    continueApprovalMutation.mutate({ execution: tool, prompt: message });
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

  function toggleTrace(messageID: string) {
    if (messageID === 'thinking') {
      setPendingTraceOpen((value) => !value);
      return;
    }
    setThread((current) => current.map((message) => (
      message.id === messageID ? { ...message, traceOpen: !message.traceOpen } : message
    )));
  }

  if (!fabVisible) {
    return null;
  }

  return (
    <AIAssistantFab
      label={t('assistant.title')}
      expanded={open}
      controls={renderPanel ? 'cheesewaf-ai-assistant-panel' : undefined}
      className={[
        renderPanel ? 'ai-fab-open' : '',
        assistantBusy ? 'ai-fab-working' : '',
      ].filter(Boolean).join(' ')}
      onActivate={toggleAssistant}
    >
      {renderPanel && (
        <section
          id="cheesewaf-ai-assistant-panel"
          role="dialog"
          aria-modal="false"
          aria-label={t('assistant.title')}
          className={open ? 'ai-assistant-panel' : 'ai-assistant-panel ai-assistant-panel-closing'}
          onAnimationEnd={(event) => {
            if (!open && event.target === event.currentTarget && event.animationName === 'assistant-panel-out') {
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
            {messages.length === 0 && (
              <section className="assistant-empty-state">
                <span className="assistant-empty-icon"><Bot size={30} /></span>
                <strong>{t('assistant.emptyTitle')}</strong>
                <p>{t('assistant.emptyHint')}</p>
                <div className="assistant-quick-prompts">
                  {assistantQuickPrompts(t).map((prompt) => (
                    <button
                      key={prompt}
                      type="button"
                      disabled={assistantBusy}
                      onClick={() => sendMessage(prompt)}
                    >
                      {prompt}
                    </button>
                  ))}
                </div>
              </section>
            )}
            {messages.map((message) => (
              <div
                key={message.id}
                className={[
                  'assistant-message',
                  `assistant-${message.role}`,
                  message.id === 'thinking' ? 'assistant-thinking' : '',
                ].filter(Boolean).join(' ')}
              >
                <div className="assistant-answer-block">
                  <SafeMarkdown text={message.text} />
                  {message.id === 'thinking' && (
                    <span className="assistant-dots" aria-hidden="true">
                      <i />
                      <i />
                      <i />
                    </span>
                  )}
                </div>
                {(message.status || message.meta) && (
                  <div className="assistant-message-status">
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
                  </div>
                )}
                {message.process && message.process.length > 0 && (
                  <section className="assistant-process" aria-label={t('assistant.processTitle')}>
                    <div className="assistant-section-head">
                      <strong>{t('assistant.processTitle')}</strong>
                      <button type="button" onClick={() => toggleProcess(message.id)}>
                        {message.processOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                        <span>{message.processOpen ? t('assistant.hideProcess') : t('assistant.showProcess')}</span>
                      </button>
                    </div>
                    {message.processOpen && (
                      <ol>
                        {message.process.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}
                      </ol>
                    )}
                  </section>
                )}
                {message.trace && message.trace.length > 0 && (
                  <section className="assistant-trace" aria-label={t('assistant.traceTitle')}>
                    <div className="assistant-section-head">
                      <strong>{t('assistant.traceTitle')}</strong>
                      <button type="button" onClick={() => toggleTrace(message.id)}>
                        {message.traceOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                        <span>{message.traceOpen ? t('assistant.hideTrace') : t('assistant.showTrace')}</span>
                      </button>
                    </div>
                    {message.traceOpen && (
                      <ol>
                        {buildTraceProcess(t, message.trace).map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}
                      </ol>
                    )}
                  </section>
                )}
                {message.tools && message.tools.length > 0 && (
                  <section className="assistant-tools" aria-label={t('assistant.toolsTitle')}>
                    <div className="assistant-section-head">
                      <strong className="assistant-section-title">{t('assistant.toolsTitle')}</strong>
                    </div>
                    {message.tools.map((tool) => {
                      const toolName = toolDisplayName(t, tool.name);
                      const sensitivity = sensitivityDisplayName(t, tool.sensitivity);
                      const approvalStatus = tool.approval?.status;
                      const approvalRunnable = approvalStatus === 'pending' || approvalStatus === 'approved';
                      const approvalExecuting = approvalStatus === 'executing' || (continuingApprovalID === tool.approval?.id && continueApprovalMutation.isPending);
                      const approvalTerminal = approvalStatus === 'executed' || approvalStatus === 'rejected' || approvalStatus === 'failed';
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
                          {tool.approval && approvalTerminal && (
                            <div className={`assistant-approval-state assistant-approval-state-${cssToken(tool.approval.status)}`}>
                              <span>{approvalStatusDisplayName(t, tool.approval.status)}</span>
                              <small>{t('assistant.approvalCompleted', { tool: toolName })}</small>
                            </div>
                          )}
                          {tool.approval && approvalExecuting && !approvalTerminal && (
                            <div className="assistant-approval assistant-approval-executing">
                              <div className="assistant-approval-top">
                                <div className="assistant-approval-head">
                                  <strong>{t('assistant.approvalExecuting')}</strong>
                                  <span>{t('assistant.approvalExecutingHint', { tool: toolName })}</span>
                                </div>
                              </div>
                            </div>
                          )}
                          {tool.approval && approvalRunnable && !approvalExecuting && (
                            <div className={`assistant-approval assistant-approval-${cssToken(tool.approval.status)}`}>
                              <div className="assistant-approval-top">
                                <div className="assistant-approval-head">
                                  <strong>{tool.approval.status === 'approved' ? t('assistant.approvalReady') : t('assistant.approvalRequired')}</strong>
                                  <span>{tool.approval.status === 'approved' ? t('assistant.approvalReadyHint', { tool: toolName }) : t('assistant.approvalTool', { tool: toolName })}</span>
                                  {tool.approval.status === 'pending' && (
                                    <small className="assistant-approval-dual-hint">{t('assistant.needsAnotherApprover')}</small>
                                  )}
                                </div>
                                <div className="assistant-approval-actions">
                                  <Button
                                    size="small"
                                    type="primary"
                                    className="assistant-approval-approve"
                                    loading={tool.approval.status === 'pending' ? approveToolMutation.isPending : continuingApprovalID === tool.approval.id && continueApprovalMutation.isPending}
                                    disabled={assistantBusy || rejectToolMutation.isPending || approveToolMutation.isPending}
                                    onClick={() => tool.approval?.status === 'pending' ? approveToolMutation.mutate(tool) : continueApproval(tool, message.prompt)}
                                  >
                                    {tool.approval.status === 'approved' ? t('assistant.continueApproved') : t('assistant.approve')}
                                  </Button>
                                  <Button
                                    size="small"
                                    status="warning"
                                    className="assistant-approval-reject"
                                    disabled={assistantBusy || rejectToolMutation.isPending || approveToolMutation.isPending}
                                    loading={rejectToolMutation.isPending}
                                    onClick={() => rejectToolMutation.mutate(tool)}
                                  >
                                    {t('assistant.reject')}
                                  </Button>
                                </div>
                              </div>
                              {tool.approval.diff && (
                                <div className="assistant-tool-section assistant-tool-section-diff">
                                  <small>{t('assistant.diffPreview')}</small>
                                  <pre>{tool.approval.diff}</pre>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </section>
                )}
              </div>
            ))}
          </div>
          <div className="assistant-input">
            <label className="assistant-deep-think-toggle">
              <Switch size="small" checked={deepThink} onChange={setDeepThink} />
              <span>{t('assistant.deepThink')}</span>
            </label>
            <Input
              value={draft}
              aria-label={t('assistant.inputLabel')}
              placeholder={t('assistant.placeholder')}
              onChange={setDraft}
              onPressEnter={submit}
            />
            <Button className="assistant-send-button" type="primary" icon={<Send size={15} />} loading={assistantBusy} onClick={submit} />
          </div>
        </section>
      )}
    </AIAssistantFab>
  );
}

function assistantQuickPrompts(t: (key: string, options?: Record<string, unknown>) => string) {
  return [
    t('assistant.quickToday'),
    t('assistant.quickWeek'),
    t('assistant.quickSettings'),
  ];
}

function lastUserPrompt(messages: AssistantMessage[]) {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    if (message.role === 'user' && message.text.trim()) {
      return message.text;
    }
    if (message.prompt?.trim()) {
      return message.prompt;
    }
  }
  return '';
}

function markApprovalStatus(messages: AssistantMessage[], approvalID: string | undefined, status: string, options: { preserveProgress?: boolean } = {}) {
  if (!approvalID) {
    return messages;
  }
  return messages.map((message) => {
    if (!message.tools) {
      return message;
    }
    return {
      ...message,
      tools: message.tools.map((tool) => {
        if (tool.approval?.id !== approvalID) {
          return tool;
        }
        const nextStatus = options.preserveProgress && approvalStatusRank(status) < approvalStatusRank(tool.approval.status)
          ? tool.approval.status
          : status;
        return { ...tool, approval: { ...tool.approval, status: nextStatus } };
      }),
    };
  });
}

export function mergeRecoveredApprovals(
  messages: AssistantMessage[],
  approvals: AIApprovalRequest[],
  definitions: Array<{ name: string; description?: string }>,
  t: (key: string, options?: Record<string, unknown>) => string,
) {
  const byID = new Map(approvals.map((approval) => [approval.id, approval]));
  const seen = new Set<string>();
  const updated = messages.map((message) => {
    if (!message.tools) {
      return message;
    }
    return {
      ...message,
      tools: message.tools.map((tool) => {
        const id = tool.approval?.id;
        const approval = id ? byID.get(id) : undefined;
        if (!approval) {
          return tool;
        }
        seen.add(approval.id);
        return { ...tool, approval };
      }),
    };
  });
  const missing = approvals.filter((approval) => !seen.has(approval.id));
  if (missing.length === 0) {
    return updated;
  }
  return [
    ...updated,
    {
      id: 'recovered-approvals',
      role: 'tool' as const,
      text: t('assistant.recoveredApprovals', { defaultValue: 'Recovered approvals' }),
      status: t('assistant.approvalRecovered', { defaultValue: 'Recovered' }),
      createdAt: missing[0]?.created_at,
      tools: missing.map((approval) => {
        const definition = definitions.find((item) => item.name === approval.tool_name);
        return {
          name: approval.tool_name,
          description: definition?.description,
          sensitivity: String(approval.sensitivity),
          args: approval.args,
          approval,
          error: approval.error,
        };
      }),
    },
  ];
}

function approvalStatusRank(status?: string) {
  switch (status) {
    case 'pending':
      return 1;
    case 'approved':
      return 2;
    case 'executing':
      return 3;
    case 'rejected':
    case 'executed':
    case 'failed':
      return 4;
    default:
      return 0;
  }
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

function buildReasoningProcess(
  t: (key: string, options?: Record<string, unknown>) => string,
  reasoning: string | undefined,
  aiUsed: boolean,
) {
  if (!aiUsed) {
    return [t('assistant.reasoningLocal')];
  }
  const text = safeAssistantDisplayText(reasoning);
  if (!text) {
    return [t('assistant.reasoningUnavailable')];
  }
  return splitReasoningLines(text, t('assistant.reasoningSummary', { summary: '' }));
}

function buildLiveReasoningProcess(t: (key: string, options?: Record<string, unknown>) => string, trace: AIAssistantTraceEvent[]) {
  const reasoning = safeAssistantDisplayText(trace.filter((event) => event.type === 'reasoning_delta').map((event) => event.message).join(''));
  if (reasoning) {
    return splitReasoningLines(reasoning, t('assistant.reasoningStreaming'));
  }
  const toolDelta = latestToolDeltaSummary(t, trace);
  if (toolDelta) {
    return [toolDelta];
  }
  const slow = [...trace].reverse().find((event) => event.type === 'provider_waiting_progress' || event.type === 'provider_first_event_slow');
  if (slow) {
    return [slow.message || t('assistant.providerSlow')];
  }
  return [t('assistant.reasoningPending')];
}

function splitReasoningLines(text: string, fallbackPrefix: string) {
  const lines = text
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length === 0) {
    return [fallbackPrefix];
  }
  if (lines.length === 1) {
    return [lines[0]];
  }
  return lines.slice(-6);
}

function buildTraceProcess(t: (key: string, options?: Record<string, unknown>) => string, trace: AIAssistantTraceEvent[]) {
  if (trace.length === 0) {
    return [t('assistant.traceWaiting')];
  }
  const regular = trace.filter((event) => !['reasoning_delta', 'reasoning_summary', 'content_delta', 'tool_call_delta'].includes(event.type));
  const formatted = regular.map((event) => formatTraceEvent(t, event));
  const toolDelta = latestToolDeltaSummary(t, trace);
  if (toolDelta) {
    formatted.push(toolDelta);
  }
  return formatted.length ? formatted : [t('assistant.traceWaiting')];
}

function latestToolDeltaSummary(t: (key: string, options?: Record<string, unknown>) => string, trace: AIAssistantTraceEvent[]) {
  const deltas = trace.filter((event) => event.type === 'tool_call_delta');
  if (deltas.length === 0) {
    return '';
  }
  const latest = deltas[deltas.length - 1];
  return t('assistant.toolDeltaLive', {
    tool: toolDisplayName(t, latest.tool_name || '-'),
    chunks: deltas.length,
  });
}

function formatTraceEvent(t: (key: string, options?: Record<string, unknown>) => string, event: AIAssistantTraceEvent) {
  switch (event.type) {
    case 'provider_response_start':
      return event.message || t('assistant.providerStarted');
    case 'provider_first_event_slow':
    case 'provider_waiting_progress':
      return event.message || t('assistant.providerSlow');
    case 'tool_call':
      return t('assistant.traceToolCall', { tool: toolDisplayName(t, event.tool_name || '-'), args: compactJson(event.args) });
    case 'tool_result':
      return t('assistant.traceToolResult', { tool: toolDisplayName(t, event.tool_name || '-'), output: summarizeOutput(event.result?.output) });
    case 'reasoning_summary':
      return t('assistant.reasoningSummary', { summary: summarizeOutput(event.message) });
    case 'approval_required':
      return t('assistant.traceApproval', { tool: toolDisplayName(t, event.tool_name || '-') });
    case 'tool_error':
    case 'planning_error':
    case 'final_error':
      return t('assistant.traceError', { step: event.tool_name || event.type, error: event.error || event.message });
    default:
      return event.message || event.type;
  }
}

function isProviderFirstTraceEvent(type: string) {
  return ['provider_response_start', 'reasoning_delta', 'content_delta', 'tool_call_delta'].includes(type);
}

function pendingAssistantText(t: (key: string, options?: Record<string, unknown>) => string, trace: AIAssistantTraceEvent[]) {
  const last = trace[trace.length - 1];
  if (!last) {
    return t('assistant.thinking');
  }
  switch (last.type) {
    case 'reasoning_delta':
      return t('assistant.reasoningStreaming');
    case 'content_delta':
      return t('assistant.answerStreaming');
    case 'tool_call_delta':
      return t('assistant.toolPlanningStreaming');
    case 'provider_response_start':
      return t('assistant.providerStarted');
    case 'provider_first_event_slow':
    case 'provider_waiting_progress':
      return last.message || t('assistant.providerSlow');
    default:
      return last.message || t('assistant.thinking');
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
  const text = safeAssistantDisplayText(value);
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
    return '0 token/s';
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} token/s`;
}

function formatMessageTime(value?: string) {
  if (!value) {
    return '';
  }
  return new Date(value).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
