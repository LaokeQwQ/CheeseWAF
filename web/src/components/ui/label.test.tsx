import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Input } from './input';
import { Label } from './label';
import { Switch } from './switch';

describe('Label', () => {
  it('associates a sibling input when callers do not supply ids', () => {
    render(
      <div>
        <Label>API key</Label>
        <Input type="password" />
      </div>,
    );

    expect(screen.getByLabelText('API key').getAttribute('type')).toBe('password');
  });

  it('associates a sibling switch when callers do not supply ids', () => {
    render(
      <div>
        <Label>Enable protection</Label>
        <Switch />
      </div>,
    );

    expect(screen.getByLabelText('Enable protection').getAttribute('role')).toBe('switch');
  });
});
