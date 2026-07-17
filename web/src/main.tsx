import React from 'react';
import ReactDOM from 'react-dom/client';
import './i18n';
import App from './App';
import { loadThemeStyles, readInitialTheme } from './themes';

async function bootstrap() {
  await Promise.all([import('./styles/global.css'), loadThemeStyles(readInitialTheme())]);
  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}

void bootstrap();
