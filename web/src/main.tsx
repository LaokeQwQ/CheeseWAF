import React from 'react';
import ReactDOM from 'react-dom/client';
import { ensureLanguage, readInitialLanguage } from './i18n';
import App from './App';
import { loadThemeStyles, readInitialTheme } from './themes';

async function bootstrap() {
  const initialLanguage = readInitialLanguage();
  await Promise.all([
    import('./styles/shadcn.css'),
    import('./styles/global.css'),
    loadThemeStyles(readInitialTheme()),
    ensureLanguage(initialLanguage),
  ]);
  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}

void bootstrap();
