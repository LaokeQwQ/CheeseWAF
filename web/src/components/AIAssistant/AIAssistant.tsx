import { useState } from 'react';
import { Button, Input, Tag } from '@arco-design/web-react';
import { useQuery } from '@tanstack/react-query';
import { Bot, Send, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { fetchLogs, fetchMonitorSummary } from '../../api/client';

export default function AIAssistant() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const { data: monitor } = useQuery({ queryKey: ['assistant-monitor'], queryFn: fetchMonitorSummary, refetchInterval: 10_000, retry: false });
  const { data: logs } = useQuery({ queryKey: ['assistant-logs'], queryFn: () => fetchLogs({ limit: 1 }), refetchInterval: 10_000, retry: false });
  const snapshot = monitor?.snapshot;
  const latest = logs?.items?.[0];
  const messages = [
    { role: 'assistant', text: t('assistant.liveSummary', { requests: snapshot?.requests ?? 0, blocked: snapshot?.blocked ?? 0 }) },
    latest ? { role: 'tool', text: `${latest.action || 'pass'} ${latest.category || latest.uri}`, status: latest.country || 'live' } : null,
  ].filter(Boolean) as Array<{ role: string; text: string; status?: string }>;

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
              <div key={`${message.role}-${message.text}`} className={`assistant-message assistant-${message.role}`}>
                <span>{message.text}</span>
                {message.status && <Tag>{message.status}</Tag>}
              </div>
            ))}
          </div>
          <div className="assistant-input">
            <Input placeholder={t('assistant.placeholder')} />
            <Button type="primary" icon={<Send size={14} />} />
          </div>
        </section>
      )}
    </>
  );
}
