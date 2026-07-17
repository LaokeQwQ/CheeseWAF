import { lazy, Suspense, useState } from 'react';
import { Button } from '@arco-design/web-react';
import { Bot } from 'lucide-react';
import { useTranslation } from 'react-i18next';

const FullAIAssistant = lazy(() => import('./AIAssistant'));

export default function AIAssistantEntry() {
  const { t } = useTranslation();
  const [loaded, setLoaded] = useState(false);

  if (loaded) {
    return (
      <Suspense fallback={<AssistantFabFallback label={t('assistant.title')} />}>
        <FullAIAssistant initialOpen />
      </Suspense>
    );
  }

  return (
    <Button
      aria-label={t('assistant.title')}
      className="ai-fab"
      type="primary"
      shape="circle"
      icon={<Bot size={36} strokeWidth={1.8} />}
      onMouseEnter={() => void import('./AIAssistant')}
      onFocus={() => void import('./AIAssistant')}
      onClick={() => setLoaded(true)}
    />
  );
}

function AssistantFabFallback({ label }: { label: string }) {
  return (
    <Button
      aria-label={label}
      className="ai-fab ai-fab-working"
      type="primary"
      shape="circle"
      loading
      icon={<Bot size={36} strokeWidth={1.8} />}
    />
  );
}
