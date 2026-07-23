import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
    i18n: { resolvedLanguage: 'zh-CN' },
  }),
}));

vi.mock('../../features/captcha', () => ({
  CAPTCHA_TYPES: ['random', 'slider', 'pow'],
  BehaviorCaptcha: ({ type, onStatusChange }: { type: string; onStatusChange?: (s: string) => void }) => {
    onStatusChange?.('ready');
    return <div data-testid="behavior-captcha">captcha:{type}</div>;
  },
}));

import CaptchaLabPage from './CaptchaLabPage';

afterEach(() => {
  cleanup();
});

describe('CaptchaLabPage', () => {
  it('renders challenge stage and switches type', async () => {
    const issue = vi.fn();
    const verify = vi.fn();
    render(<CaptchaLabPage issue={issue} verify={verify} />);
    expect(screen.getByText('captchaLab.title')).toBeTruthy();
    expect(screen.getByTestId('behavior-captcha').textContent).toContain('captcha:random');
    const select = document.querySelector('select') as HTMLSelectElement;
    expect(select).toBeTruthy();
    expect(select.value).toBe('random');
    fireEvent.change(select, { target: { value: 'slider' } });
    await waitFor(() => {
      expect(screen.getByTestId('behavior-captcha').textContent).toContain('captcha:slider');
    });
  });

  it('regenerate remounts captcha via generation key', async () => {
    render(<CaptchaLabPage issue={vi.fn()} verify={vi.fn()} />);
    const before = screen.getByTestId('behavior-captcha');
    fireEvent.click(screen.getByRole('button', { name: /captchaLab.regenerate/i }));
    await waitFor(() => {
      expect(screen.getByTestId('behavior-captcha')).not.toBe(before);
    });
  });
});
