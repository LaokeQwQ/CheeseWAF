import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  fetchReviewItems: vi.fn(),
  fetchSites: vi.fn(),
  decideReviewItem: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key, i18n: { resolvedLanguage: 'zh-CN' } }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import ReviewPage from './ReviewPage';

const item = {
  id: 'rev-1',
  trace_id: 'trace-1',
  site_id: 'site-a',
  client_ip: '203.0.113.9',
  method: 'GET',
  uri: '/search?s=eval',
  category: 'webshell',
  severity: 'high',
  payload: 'eval($_GET[cmd])',
  protection_level: 3,
  shape: 'embedded',
  fingerprint: 'aabbccddeeff0011',
  status: 'pending',
  created_at: '2026-08-14T10:00:00Z',
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <ReviewPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchSites.mockResolvedValue([{ id: 'site-a', name: 'Site A' }]);
  apiMocks.fetchReviewItems.mockImplementation((params: { search?: string }) => {
    const matches = !params.search || Object.values(item).some((value) => String(value ?? '').toLowerCase().includes(params.search!.toLowerCase()));
    return Promise.resolve({ items: matches ? [item] : [], total: matches ? 1 : 0 });
  });
  apiMocks.decideReviewItem.mockResolvedValue({ ...item, status: 'blocked', decision: 'block_payload' });
});

afterEach(() => {
  cleanup();
});

describe('ReviewPage', () => {
  it('lists pending items and converts to a payload block', async () => {
    renderPage();
    expect(await screen.findByText('/search?s=eval')).toBeTruthy();
    fireEvent.click(screen.getByText('review.blockPayload'));
    await waitFor(() => {
      expect(apiMocks.decideReviewItem).toHaveBeenCalledWith('rev-1', 'block_payload');
    });
  });

  it('converts a pending item to a fingerprint block', async () => {
    renderPage();
    expect(await screen.findByText('aabbccddeeff0011')).toBeTruthy();
    fireEvent.click(screen.getByText('review.blockFingerprint'));
    await waitFor(() => {
      expect(apiMocks.decideReviewItem).toHaveBeenCalledWith('rev-1', 'block_fingerprint');
    });
  });

  it('converts a pending item to URL and IP blocks', async () => {
    renderPage();
    expect(await screen.findByText('/search?s=eval')).toBeTruthy();
    fireEvent.click(screen.getByText('review.blockUri'));
    await waitFor(() => {
      expect(apiMocks.decideReviewItem).toHaveBeenCalledWith('rev-1', 'block_uri');
    });
    fireEvent.click(screen.getByText('review.blockIp'));
    await waitFor(() => {
      expect(apiMocks.decideReviewItem).toHaveBeenCalledWith('rev-1', 'block_ip');
    });
  });

  it('allows a pending item and can add a whitelist', async () => {
    renderPage();
    expect(await screen.findByText('/search?s=eval')).toBeTruthy();
    fireEvent.click(screen.getByText('review.allow'));
    await waitFor(() => {
      expect(apiMocks.decideReviewItem).toHaveBeenCalledWith('rev-1', 'allow');
    });
    fireEvent.click(screen.getByText('review.allowWhitelist'));
    await waitFor(() => {
      expect(apiMocks.decideReviewItem).toHaveBeenCalledWith('rev-1', 'allow_whitelist');
    });
  });

  it('lets an already-blocked item add a lasting fingerprint block', async () => {
    apiMocks.fetchReviewItems.mockResolvedValue({
      items: [{ ...item, status: 'blocked', decision: 'block_now', protection_level: 5 }],
      total: 1,
    });
    renderPage();
    expect(await screen.findByText('aabbccddeeff0011')).toBeTruthy();
    fireEvent.click(screen.getByText('review.blockFingerprint'));
    await waitFor(() => {
      expect(apiMocks.decideReviewItem).toHaveBeenCalledWith('rev-1', 'block_fingerprint');
    });
    expect(screen.queryByText('review.allow')).toBeNull();
  });

  it('sends review search to the server', async () => {
    renderPage();
    await screen.findByText('/search?s=eval');
    fireEvent.change(screen.getByPlaceholderText('common.search'), { target: { value: 'aabbcc' } });
    await waitFor(() => expect(apiMocks.fetchReviewItems).toHaveBeenCalledWith(expect.objectContaining({ search: 'aabbcc', limit: 8 })));
    expect(await screen.findByText('aabbccddeeff0011')).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText('common.search'), { target: { value: 'not-found' } });
    await waitFor(() => expect(apiMocks.fetchReviewItems).toHaveBeenCalledWith(expect.objectContaining({ search: 'not-found' })));
    await waitFor(() => expect(screen.queryByText('/search?s=eval')).toBeNull());
  });

  it('uses a fixed watermark and stable before cursor for the next page', async () => {
    const pageItems = Array.from({ length: 9 }, (_, index) => ({
      ...item,
      id: `review-${index + 1}`,
      uri: `/review/page/${index + 1}`,
      created_at: `2026-08-14T10:${String(20 - index).padStart(2, '0')}:00Z`,
    }));
    apiMocks.fetchReviewItems.mockImplementation((params: { before?: string }) => Promise.resolve(
      params.before
        ? { items: [pageItems[8]], total: 1 }
        : { items: pageItems.slice(0, 8), total: 9 },
    ));
    renderPage();
    expect(await screen.findByText('/review/page/8')).toBeTruthy();
    fireEvent.click(await screen.findByText('common.next'));
    await waitFor(() => expect(apiMocks.fetchReviewItems).toHaveBeenCalledWith(expect.objectContaining({
      before: pageItems[7].created_at,
      before_id: pageItems[7].id,
      watermark: pageItems[0].created_at,
      watermark_id: pageItems[0].id,
    })));
    expect(await screen.findByText('/review/page/9')).toBeTruthy();
  });

  it('does not advance until the first page has a valid watermark', async () => {
    const pageItems = Array.from({ length: 8 }, (_, index) => ({
      ...item,
      id: `review-${index + 1}`,
      uri: `/review/page/${index + 1}`,
      created_at: index === 0 ? '' : `2026-08-14T10:${String(20 - index).padStart(2, '0')}:00Z`,
    }));
    apiMocks.fetchReviewItems.mockResolvedValue({ items: pageItems, total: 9 });

    renderPage();

    expect(await screen.findByText('/review/page/8')).toBeTruthy();
    expect((screen.getByText('common.next') as HTMLButtonElement).disabled).toBe(true);
  });
});
