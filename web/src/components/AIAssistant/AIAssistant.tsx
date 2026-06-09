import { useEffect, useMemo, useRef, useState } from 'react';
import { Button, Input, Tag } from '@arco-design/web-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Bot, ChevronDown, ChevronUp, Send, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { askAIAssistant, fetchLogs, fetchMonitorSummary } from '../../api/client';

type AssistantMessage = {
  id: string;
  role: 'user' | 'assistant' | 'tool';
  text: string;
  status?: string;
  createdAt?: string;
  meta?: AssistantMeta;
  process?: string[];
  processOpen?: boolean;
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
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [renderPanel, setRenderPanel] = useState(false);
  const [draft, setDraft] = useState('');
  const [thread, setThread] = useState<AssistantMessage[]>([]);
  const [pendingElapsedMs, setPendingElapsedMs] = useState(0);
  const [thinkingProcessOpen, setThinkingProcessOpen] = useState(true);
  const pendingRef = useRef<{ startedAt: number; createdAt: string; inputTokens: number } | null>(null);
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
    mutationFn: (message: string) => askAIAssistant(message, 30),
    onSuccess: (reply) => {
      const pending = pendingRef.current;
      const totalMs = pending ? performance.now() - pending.startedAt : 0;
      const outputTokens = reply.output_tokens || estimateTokens(reply.answer);
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
          process: buildProcessSummary(t, reply.ai_used, reply.events, reply.blocked, reply.challenge),
        },
      ]);
      pendingRef.current = null;
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
          process: [t('assistant.processError')],
        },
      ]);
      pendingRef.current = null;
    },
  });

  useEffect(() => {
    if (open) {
      setRenderPanel(true);
    }
  }, [open]);

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
    {
      id: 'live',
      role: 'tool',
      text: t('assistant.liveSummary', { requests: liveContext.requests, blocked: liveContext.blocked, events: liveContext.events }),
      status: 'live',
    },
    ...(liveContext.latest ? [{
      id: 'latest',
      role: 'tool' as const,
      text: `${liveContext.latest.action || 'log'} ${liveContext.latest.category || liveContext.latest.uri}`,
      status: liveContext.latest.country || liveContext.latest.client_ip || 'event',
    }] : []),
    ...thread,
    ...(askMutation.isPending ? [{
      id: 'thinking',
      role: 'assistant' as const,
      text: t('assistant.thinking'),
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
      process: [
        t('assistant.processContext', { events: liveContext.events, blocked: liveContext.blocked, challenge: 0 }),
        t('assistant.processSafety'),
      ],
      processOpen: thinkingProcessOpen,
    }] : []),
  ];

  function submit() {
    const message = draft.trim();
    if (!message) {
      return;
    }
    setDraft('');
    setPendingElapsedMs(0);
    setThinkingProcessOpen(true);
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
        onClick={() => setOpen((value) => !value)}
      />
      {renderPanel && (
        <section
          className={open ? 'ai-assistant-panel' : 'ai-assistant-panel ai-assistant-panel-closing'}
          onAnimationEnd={() => {
            if (!open) {
              setRenderPanel(false);
            }
          }}
        >
          <header>
            <strong>{t('assistant.title')}</strong>
            <Button size="mini" icon={<X size={14} />} onClick={() => setOpen(false)} />
          </header>
          <div className="assistant-thread" aria-live="polite">
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

function buildProcessSummary(
  t: (key: string, options?: Record<string, unknown>) => string,
  aiUsed: boolean,
  events: number,
  blocked: number,
  challenge: number,
) {
  return [
    t('assistant.processContext', { events, blocked, challenge }),
    aiUsed ? t('assistant.processProvider') : t('assistant.processLocal'),
    t('assistant.processSafety'),
  ];
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
