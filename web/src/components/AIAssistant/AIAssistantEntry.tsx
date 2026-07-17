import { lazy, Suspense, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAppStore } from '../../stores';
import AIAssistantFab from './AIAssistantFab';

const FullAIAssistant = lazy(() => import('./AIAssistant'));

export default function AIAssistantEntry() {
  const { t } = useTranslation();
  const fabVisible = useAppStore((state) => state.aiAssistantFabVisible);
  const [loaded, setLoaded] = useState(false);

  if (!fabVisible) {
    return null;
  }

  if (loaded) {
    return (
      <Suspense
        fallback={(
          <AIAssistantFab
            label={t('assistant.title')}
            className="ai-fab-working"
            loading
            onActivate={() => undefined}
          />
        )}
      >
        <FullAIAssistant initialOpen />
      </Suspense>
    );
  }

  return (
    <AIAssistantFab
      label={t('assistant.title')}
      onActivate={() => {
        void import('./AIAssistant');
        setLoaded(true);
      }}
    />
  );
}
