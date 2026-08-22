import { cleanup, render, screen } from '@testing-library/react';
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

const useAppStoreMock = vi.fn();

vi.mock('../../stores', () => ({
  useAppStore: (selector: (state: { theme: string }) => unknown) => useAppStoreMock(selector),
}));

let lastProps: { theme?: string } | undefined;
vi.mock('sonner', () => ({
  Toaster: (props: { theme?: string }) => {
    lastProps = props;
    return <div data-testid="toaster" data-theme={props.theme} />;
  },
}));

import { Toaster } from './sonner';

beforeEach(() => {
  useAppStoreMock.mockReset();
  lastProps = undefined;
});

afterEach(() => {
  cleanup();
});

describe('Toaster theme', () => {
  it('maps dark and blackGold app themes to dark toasts', () => {
    useAppStoreMock.mockImplementation((selector: (s: { theme: string }) => unknown) => selector({ theme: 'dark' }));
    render(<Toaster />);
    expect(screen.getByTestId('toaster').getAttribute('data-theme')).toBe('dark');

    cleanup();
    useAppStoreMock.mockImplementation((selector: (s: { theme: string }) => unknown) => selector({ theme: 'blackGold' }));
    render(<Toaster />);
    expect(screen.getByTestId('toaster').getAttribute('data-theme')).toBe('dark');
  });

  it('maps light and other color schemes to light toasts', () => {
    for (const theme of ['light', 'blueWhite', 'pinkWhite', 'mikuGreen']) {
      cleanup();
      useAppStoreMock.mockImplementation((selector: (s: { theme: string }) => unknown) => selector({ theme }));
      render(<Toaster />);
      expect(screen.getByTestId('toaster').getAttribute('data-theme')).toBe('light');
    }
  });
});
