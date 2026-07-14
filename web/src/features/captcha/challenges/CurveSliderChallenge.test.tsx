import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CurveSliderChallenge } from './CurveSliderChallenge';

const image = 'data:image/png;base64,iVBORw0KGgo=';

afterEach(cleanup);

describe('CurveSliderChallenge', () => {
  it('reshapes the foreground curve and submits only on release', () => {
    const onSubmit = vi.fn();
    render(<CurveSliderChallenge imageSrc={image} version={2} onSubmit={onSubmit} />);
    const slider = screen.getByRole('slider');
    fireEvent.pointerDown(slider, { pointerId: 4 });
    fireEvent.change(slider, { target: { value: '7200' } });
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByTestId('curve-slider-foreground').getAttribute('data-progress')).toBe('7200');
    fireEvent.pointerUp(slider, { pointerId: 4 });
    expect(onSubmit).toHaveBeenCalledTimes(1);
    const response = onSubmit.mock.calls[0][0];
    expect(response.point).toEqual({ x: 7200, y: 5000 });
    expect(response.track.length).toBeGreaterThanOrEqual(3);
    expect(response.track[0]).toMatchObject({ type: 'down' });
    expect(response.track.at(-1)).toMatchObject({ type: 'up' });
    expect(response.duration_ms).toEqual(expect.any(Number));
  });

  it('does not submit when disabled or cancelled', () => {
    const onSubmit = vi.fn();
    const { rerender } = render(<CurveSliderChallenge imageSrc={image} onSubmit={onSubmit} />);
    let slider = screen.getByRole('slider');
    fireEvent.pointerDown(slider, { pointerId: 2 });
    fireEvent.pointerCancel(slider, { pointerId: 2 });
    expect(onSubmit).not.toHaveBeenCalled();
    rerender(<CurveSliderChallenge imageSrc={image} disabled onSubmit={onSubmit} />);
    slider = screen.getByRole('slider');
    expect((slider as HTMLInputElement).disabled).toBe(true);
  });

  it.each([[1, 'M 9 66'], [2, 'M 9 61.52'], [3, 'M 9 56.08']] as const)('renders version %i from the shared curve contract', (version, start) => {
    render(<CurveSliderChallenge imageSrc={image} version={version} initialValue={5000} onSubmit={vi.fn()} />);
    const path = screen.getByTestId('curve-slider-foreground');
    expect(path.getAttribute('d')).toContain(start);
    expect(path.getAttribute('d')?.split(' L ')).toHaveLength(33);
  });
});
