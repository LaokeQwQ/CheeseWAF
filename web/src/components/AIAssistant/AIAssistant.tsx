import { useState } from 'react';
import { Button, Input, Tag } from '@arco-design/web-react';
import { Bot, Check, Send, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

export default function AIAssistant() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const messages = [
    { role: 'assistant', text: t('assistant.seed') },
    { role: 'tool', text: 'system_summary', status: 'read-only' },
  ];
  return (
    <>
      <Button className="ai-fab" type="primary" shape="circle" icon={<Bot size={18} />} onClick={() => setOpen((value) => !value)} />
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
            <div className="assistant-approval">
              <span>{t('assistant.approval')}</span>
              <Button size="mini" icon={<Check size={13} />}>{t('assistant.approve')}</Button>
              <Button size="mini" status="danger" icon={<X size={13} />}>{t('assistant.reject')}</Button>
            </div>
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
