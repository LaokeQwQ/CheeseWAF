import { useMemo, useState } from 'react';
import { Button, Input, Tag } from '@arco-design/web-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Bot, Send, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { askAIAssistant, fetchLogs, fetchMonitorSummary } from '../../api/client';

type AssistantMessage = {
  id: string;
  role: 'user' | 'assistant' | 'tool';
  text: string;
  status?: string;
};

export default function AIAssistant() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState('');
  const [thread, setThread] = useState<AssistantMessage[]>([]);
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
      setThread((current) => [
        ...current,
        {
          id: `assistant-${Date.now()}`,
          role: 'assistant',
          text: reply.answer,
          status: reply.ai_used ? 'AI' : t('ai.heuristicUsed'),
        },
      ]);
    },
    onError: (error) => {
      setThread((current) => [
        ...current,
        { id: `assistant-error-${Date.now()}`, role: 'assistant', text: error.message, status: 'error' },
      ]);
    },
  });

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
  ];

  function submit() {
    const message = draft.trim();
    if (!message) {
      return;
    }
    setDraft('');
    setThread((current) => [...current, { id: `user-${Date.now()}`, role: 'user', text: message }]);
    askMutation.mutate(message);
  }

  return (
    <>
      <Button className="ai-fab" type="primary" shape="circle" icon={<Bot size={26} />} onClick={() => setOpen((value) => !value)} />
      {open && (
        <section className="ai-assistant-panel">
          <header>
            <strong>{t('assistant.title')}</strong>
            <Button size="mini" icon={<X size={14} />} onClick={() => setOpen(false)} />
          </header>
          <div className="assistant-thread">
            {messages.map((message) => (
              <div key={message.id} className={`assistant-message assistant-${message.role}`}>
                <span>{message.text}</span>
                {message.status && <Tag>{message.status}</Tag>}
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
