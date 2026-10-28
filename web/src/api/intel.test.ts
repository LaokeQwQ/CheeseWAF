import { beforeEach, describe, expect, it, vi } from 'vitest';

const client = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));

import type * as ClientModule from './client';

vi.mock('./client', async (importOriginal) => {
  const actual = await importOriginal<typeof ClientModule>();
  return { ...actual, apiClient: client };
});

import { APIRequestError } from './client';
import {
  approveIntelCandidate,
  fetchIntelCandidate,
  fetchIntelCandidates,
  fetchIntelImpact,
  fetchIntelItems,
  importIntelURL,
  rejectIntelCandidate,
} from './intel';

describe('intel API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('posts an advisory import with the server-side fetch budget', async () => {
    const response = {
      job_id: 'job-1',
      item: { id: 'item-1', source_id: 'source-1' },
      candidate: { id: 'candidate-1' },
      impact: { verdict: 'needs-review' },
      candidates: [{ candidate: { id: 'candidate-1' }, impact: { verdict: 'needs-review' } }],
      item_created: true,
      candidate_created: true,
    };
    client.post.mockResolvedValue({ data: response });

    await expect(importIntelURL({ url: 'https://vendor.example/a', site_id: 'site-a', path_prefix: '/api' }))
      .resolves.toEqual(response);
    expect(client.post).toHaveBeenCalledWith(
      '/intel/import-url',
      { url: 'https://vendor.example/a', site_id: 'site-a', path_prefix: '/api' },
      { timeout: 60_000 },
    );
  });

  it('returns raw intel lists and omits empty candidate filters', async () => {
    client.get.mockResolvedValue({ data: { candidates: [], count: 0 } });

    await expect(fetchIntelCandidates()).resolves.toEqual({ candidates: [], count: 0 });
    expect(client.get).toHaveBeenCalledWith('/intel/candidates', undefined);

    await fetchIntelCandidates({ site_id: 'site-a', state: 'draft', limit: 25 });
    expect(client.get).toHaveBeenLastCalledWith('/intel/candidates', {
      params: { site_id: 'site-a', state: 'draft', limit: 25 },
    });
  });

  it('passes the item limit and impact site filter as query params', async () => {
    client.get.mockResolvedValue({ data: { items: [], count: 0 } });
    await fetchIntelItems();
    expect(client.get).toHaveBeenCalledWith('/intel/items', { params: { limit: 50 } });

    client.get.mockResolvedValue({ data: { site_id: 'site-a', profiles: 0, assessments: [] } });
    await fetchIntelImpact('site-a');
    expect(client.get).toHaveBeenLastCalledWith('/intel/impact', { params: { site_id: 'site-a' } });
  });

  it('encodes candidate ids for detail, approval, and rejection', async () => {
    client.get.mockResolvedValue({ data: { candidate: { id: 'a/b' } } });
    await fetchIntelCandidate('a/b');
    expect(client.get).toHaveBeenCalledWith('/intel/candidates/a%2Fb');

    client.post.mockResolvedValue({ data: { candidate: { id: 'a/b' } } });
    await approveIntelCandidate('a/b', { approved_by: 'alice', confirm: true, action: 'log' });
    expect(client.post).toHaveBeenCalledWith('/intel/candidates/a%2Fb/approve', {
      approved_by: 'alice',
      confirm: true,
      action: 'log',
    });

    await rejectIntelCandidate('a/b');
    expect(client.post).toHaveBeenCalledWith('/intel/candidates/a%2Fb/reject', {});
  });

  it('turns the intel error envelope into an APIRequestError with review reasons', async () => {
    client.post.mockRejectedValue({
      isAxiosError: true,
      message: 'Request failed with status code 409',
      response: {
        status: 409,
        data: {
          error: {
            code: 'impact_insufficient',
            message: 'block promotion requires impact evidence',
            reasons: ['no profiles match the candidate scope'],
          },
        },
      },
    });

    const rejection = approveIntelCandidate('candidate-1', { approved_by: 'alice', confirm: true, action: 'block' });
    await expect(rejection).rejects.toBeInstanceOf(APIRequestError);
    await expect(rejection).rejects.toMatchObject({
      code: 'impact_insufficient',
      status: 409,
      message: 'block promotion requires impact evidence (no profiles match the candidate scope)',
    });
  });

  it('maps transport failures to the shared network error', async () => {
    client.get.mockRejectedValue({ isAxiosError: true, message: 'Network Error', response: undefined });

    await expect(fetchIntelCandidate('candidate-1')).rejects.toMatchObject({
      code: 'NETWORK_ERROR',
      status: undefined,
    });
  });
});
