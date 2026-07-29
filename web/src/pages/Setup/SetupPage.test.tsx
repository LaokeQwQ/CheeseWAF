import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  setupAdmin: vi.fn(),
}));

const navigateMock = vi.fn();

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigateMock };
});

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import SetupPage from './SetupPage';

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe('SetupPage', () => {
  it('submits admin bootstrap with form values', async () => {
    apiMocks.setupAdmin.mockResolvedValue({ setup_complete: true });
    render(<SetupPage />);
    fireEvent.change(screen.getByPlaceholderText('admin'), { target: { value: 'root-admin' } });
    fireEvent.change(screen.getByPlaceholderText('********'), { target: { value: 'S3cure-Pass!' } });
    fireEvent.click(screen.getByRole('button', { name: 'common.next' }));
    await waitFor(() => expect(apiMocks.setupAdmin).toHaveBeenCalled());
    expect(apiMocks.setupAdmin).toHaveBeenCalledWith(
      'root-admin',
      'S3cure-Pass!',
      expect.any(String),
      expect.any(String),
    );
    await waitFor(() => {
      expect(document.querySelector('.form-success')?.textContent).toBe('setup.complete');
    });
    await vi.advanceTimersByTimeAsync(900);
    expect(navigateMock).toHaveBeenCalledWith('/login', { replace: true });
  });

  it('surfaces setup API failures', async () => {
    apiMocks.setupAdmin.mockRejectedValue(new Error('username already exists'));
    render(<SetupPage />);
    fireEvent.change(screen.getByPlaceholderText('admin'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByPlaceholderText('********'), { target: { value: 'x' } });
    fireEvent.click(screen.getByRole('button', { name: 'common.next' }));
    expect(await screen.findByText('username already exists')).toBeTruthy();
    expect(navigateMock).not.toHaveBeenCalled();
  });
});
