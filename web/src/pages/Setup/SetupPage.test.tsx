import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  setupAdmin: vi.fn(),
  unwrapAPIResponse: vi.fn(),
}));

const navigateMock = vi.fn();

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string, opts?: { defaultValue?: string }) => opts?.defaultValue ?? key }),
}));

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigateMock };
});

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return {
    ...actual,
    setupAdmin: apiMocks.setupAdmin,
    unwrapAPIResponse: apiMocks.unwrapAPIResponse,
    apiClient: {
      post: vi.fn(() => Promise.resolve({})),
      patch: vi.fn(() => Promise.resolve({})),
    },
  };
});

import SetupPage from './SetupPage';

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers({ shouldAdvanceTime: true });
  apiMocks.unwrapAPIResponse.mockResolvedValue({
    probe: {
      profile: 'medium',
      cpu_logical: 4,
      memory_total_mb: 8192,
      disk_write_mbps: 100,
      incomplete: false,
    },
  });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

async function advanceToAccountStep() {
  render(<SetupPage />);
  await waitFor(() => expect(screen.getByText(/Recommended:/i)).toBeTruthy());
  fireEvent.click(screen.getByRole('button', { name: 'Next' }));
  fireEvent.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(screen.getByPlaceholderText('admin')).toBeTruthy());
}

describe('SetupPage', () => {
  it('submits admin bootstrap with form values after confirmation', async () => {
    apiMocks.setupAdmin.mockResolvedValue({ setup_complete: true });
    await advanceToAccountStep();

    fireEvent.change(screen.getByPlaceholderText('admin'), { target: { value: 'root-admin' } });
    fireEvent.change(screen.getByPlaceholderText('********'), { target: { value: 'S3cure-Pass!' } });
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));

    await waitFor(() => expect(screen.getByRole('checkbox')).toBeTruthy());
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'setup.complete' }));

    await waitFor(() => expect(apiMocks.setupAdmin).toHaveBeenCalled());
    expect(apiMocks.setupAdmin).toHaveBeenCalledWith(
      'root-admin',
      'S3cure-Pass!',
      expect.any(String),
      expect.any(String),
    );
    await vi.advanceTimersByTimeAsync(900);
    expect(navigateMock).toHaveBeenCalledWith('/login', { replace: true });
  });

  it('surfaces setup API failures', async () => {
    apiMocks.setupAdmin.mockRejectedValue(new Error('username already exists'));
    await advanceToAccountStep();

    fireEvent.change(screen.getByPlaceholderText('admin'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByPlaceholderText('********'), { target: { value: 'N7v!mKq2PxR' } });
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(screen.getByRole('checkbox')).toBeTruthy());
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'setup.complete' }));

    expect(await screen.findByText('username already exists')).toBeTruthy();
    expect(navigateMock).not.toHaveBeenCalled();
  });
});
