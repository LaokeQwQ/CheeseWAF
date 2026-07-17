import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  deleteCustomBlockPage: vi.fn(),
  fetchBlockPageConfig: vi.fn(),
  fetchBlockTemplates: vi.fn(),
  previewBlockPageConfig: vi.fn(),
  updateBlockPageConfig: vi.fn(),
  uploadBlockPageHTML: vi.fn(),
}));

const messageMocks = vi.hoisted(() => ({
  error: vi.fn(),
  success: vi.fn(),
  warning: vi.fn(),
}));

vi.mock('@arco-design/web-react', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@arco-design/web-react')>();
  return { ...actual, Message: messageMocks };
});

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import { APIRequestError } from '../../api/client';
import BlockPagesPage, { sanitizeBlockPreviewHTML } from './BlockPagesPage';

const template = {
  id: 'minimal',
  name: 'Minimal',
  description: 'Minimal fixture',
  html: '<!doctype html><html><body><h1>Blocked</h1></body></html>',
};

const config = {
  template_id: 'minimal',
  custom_enabled: false,
  custom_html: '',
};

function renderBlockPages() {
  const client = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false },
    },
  });
  render(
    <QueryClientProvider client={client}>
      <BlockPagesPage />
    </QueryClientProvider>,
  );
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchBlockTemplates.mockResolvedValue([template]);
  apiMocks.fetchBlockPageConfig.mockResolvedValue(config);
  apiMocks.previewBlockPageConfig.mockResolvedValue({ html: template.html, event_id: 'event-1', trace_id: 'trace-1' });
  apiMocks.updateBlockPageConfig.mockImplementation(async (payload) => payload);
  apiMocks.deleteCustomBlockPage.mockResolvedValue(config);
});

afterEach(() => cleanup());

describe('sanitizeBlockPreviewHTML', () => {
  it('strips scripts, base, action/formaction, and dangerous URL schemes', () => {
    const dirty = `
      <!doctype html>
      <html>
        <head>
          <base href="https://evil.example/">
          <script>alert(1)</script>
        </head>
        <body>
          <form action="https://evil.example/steal" formaction="javascript:alert(1)">
            <button formaction="javascript:alert(2)">go</button>
          </form>
          <a href="javascript:alert(3)">link</a>
          <img src="data:text/html,<script>alert(4)</script>" onerror="alert(5)">
        </body>
      </html>
    `;
    const clean = sanitizeBlockPreviewHTML(dirty);
    expect(clean).not.toMatch(/<script/i);
    expect(clean).not.toMatch(/<base/i);
    expect(clean).not.toMatch(/\baction=/i);
    expect(clean).not.toMatch(/formaction/i);
    expect(clean).not.toMatch(/javascript:/i);
    expect(clean).not.toMatch(/onerror/i);
    expect(clean).not.toMatch(/data:text\/html/i);
  });
});

describe('BlockPagesPage query and write states', () => {
  it('hides the active-success badge and disables writes when config loading fails', async () => {
    apiMocks.fetchBlockPageConfig.mockRejectedValue(new APIRequestError('config unavailable', 'BLOCK_CONFIG_FAILED', 503));
    renderBlockPages();

    expect((await screen.findByRole('alert')).textContent).toContain('blockPages.loadFailed');
    expect(screen.queryByText('blockPages.builtInActive')).toBeNull();
    expect((screen.getByRole('button', { name: 'blockPages.uploadHtml' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'blockPages.saveCustom' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'blockPages.useBuiltIn' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('only disables built-in template writes when the template list fails', async () => {
    apiMocks.fetchBlockTemplates.mockRejectedValue(new APIRequestError('templates unavailable', 'BLOCK_TEMPLATES_FAILED', 503));
    renderBlockPages();

    await screen.findByRole('alert');
    expect(screen.getByText('blockPages.builtInActive')).toBeTruthy();
    expect((screen.getByRole('button', { name: 'blockPages.useBuiltIn' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'blockPages.saveCustom' }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('reports a failed custom save without showing success', async () => {
    apiMocks.updateBlockPageConfig.mockRejectedValue(new APIRequestError('custom save failed', 'BLOCK_WRITE_FAILED', 500));
    renderBlockPages();
    await screen.findByText('blockPages.builtInActive');
    const editor = await screen.findByPlaceholderText('blockPages.editorPlaceholder');
    fireEvent.change(editor, { target: { value: '<html><body>Draft</body></html>' } });
    fireEvent.click(screen.getByRole('button', { name: 'blockPages.saveCustom' }));

    await waitFor(() => expect(messageMocks.error).toHaveBeenCalledWith('custom save failed'));
    expect(messageMocks.success).not.toHaveBeenCalled();
  });
});
