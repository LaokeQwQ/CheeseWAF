import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import SafeMarkdown from './SafeMarkdown';

describe('SafeMarkdown', () => {
  it('keeps scripts, images, and links inert text', () => {
    render(<SafeMarkdown text={'<script>alert(1)</script> ![pixel](https://example.com/pixel.png) [docs](https://example.com/docs)'} />);

    expect(document.querySelector('script')).toBeNull();
    expect(document.querySelector('img')).toBeNull();
    expect(document.querySelector('a')).toBeNull();
    expect(screen.getByText('<script>alert(1)</script> ![pixel](https://example.com/pixel.png) [docs](https://example.com/docs)')).toBeTruthy();
  });

  it('renders supported inline markdown and fenced code as inert elements', () => {
    render(<SafeMarkdown text={'Use **bold** and `inline`.' + '\n\n```ts\nconst answer = 42;\n```'} />);

    expect(screen.getByText('bold').tagName).toBe('STRONG');
    expect(screen.getByText('inline').tagName).toBe('CODE');
    expect(screen.getByText('const answer = 42;').closest('pre')).toBeTruthy();
    expect(screen.getByText('const answer = 42;').getAttribute('data-language')).toBe('ts');
  });

  it('renders markdown tables with headers and rows', () => {
    render(<SafeMarkdown text={'| Name | Status |\n| --- | --- |\n| api | healthy |'} />);

    expect(screen.getByRole('table')).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Name' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Status' })).toBeTruthy();
    expect(screen.getByRole('cell', { name: 'api' })).toBeTruthy();
    expect(screen.getByRole('cell', { name: 'healthy' })).toBeTruthy();
  });
});
