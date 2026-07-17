import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CurveSliderChallenge } from './CurveSliderChallenge';

const image = 'data:image/png;base64,iVBORw0KGgo=';
const piece = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('CurveSliderChallenge', () => {
  it('translates the solid curve piece and submits only on release', () => {
    const onSubmit = vi.fn();
    render(
      <CurveSliderChallenge
        imageSrc={image}
        pieceSrc={piece}
        onSubmit={onSubmit}
      />,
    );
    const slider = screen.getByRole('slider');
    fireEvent.pointerDown(slider, { pointerId: 4 });
    fireEvent.change(slider, { target: { value: '7200' } });
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByTestId('curve-slider-piece').getAttribute('data-offset')).toBe('7.04');
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
    const { rerender } = render(
      <CurveSliderChallenge imageSrc={image} pieceSrc={piece} onSubmit={onSubmit} />,
    );
    let slider = screen.getByRole('slider');
    fireEvent.pointerDown(slider, { pointerId: 2 });
    fireEvent.pointerCancel(slider, { pointerId: 2 });
    expect(onSubmit).not.toHaveBeenCalled();
    rerender(<CurveSliderChallenge imageSrc={image} pieceSrc={piece} disabled onSubmit={onSubmit} />);
    slider = screen.getByRole('slider');
    expect((slider as HTMLInputElement).disabled).toBe(true);
  });

  it('submits the latest DOM value even when release immediately follows input', () => {
    const onSubmit = vi.fn();
    render(<CurveSliderChallenge imageSrc={image} pieceSrc={piece} onSubmit={onSubmit} />);
    const slider = screen.getByRole('slider');
    fireEvent.pointerDown(slider, { pointerId: 9 });
    fireEvent.input(slider, { target: { value: '8300' } });
    fireEvent.pointerUp(slider, { pointerId: 9 });
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({
      point: { x: 8300, y: 5000 },
      track: expect.arrayContaining([expect.objectContaining({ x: 8300, type: 'up' })]),
    }));
  });

  it('keeps keyboard adjustments open until Enter and honors the issued minimum duration', () => {
    const onSubmit = vi.fn();
    render(
      <CurveSliderChallenge
        imageSrc={image}
        pieceSrc={piece}
        minDurationMs={10_000}
        alt="Align curve"
        onSubmit={onSubmit}
      />,
    );
    const slider = screen.getByRole('slider', { name: 'Align curve' });
    fireEvent.keyDown(slider, { key: 'PageUp' });
    fireEvent.keyUp(slider, { key: 'PageUp' });
    expect(onSubmit).not.toHaveBeenCalled();
    expect((slider as HTMLInputElement).value).toBe('6000');

    fireEvent.keyDown(slider, { key: 'Enter' });
    expect(onSubmit).toHaveBeenCalledTimes(1);
    const response = onSubmit.mock.calls[0][0];
    expect(response).toMatchObject({
      point: { x: 6000, y: 5000 },
      duration_ms: 10_000,
    });
    expect(response.track).toEqual([
      expect.objectContaining({ x: 5000, y: 5000, t: 0, type: 'down' }),
      expect.objectContaining({ x: 5250, y: 5000, type: 'move' }),
      expect.objectContaining({ x: 5500, y: 5000, type: 'move' }),
      expect.objectContaining({ x: 5750, y: 5000, type: 'move' }),
      expect.objectContaining({ x: 6000, y: 5000, type: 'move' }),
      expect.objectContaining({ x: 6000, y: 5000, t: 10_000, type: 'up' }),
    ]);
  });

  it('supports Space submission and exposes a focusable slider control', () => {
    const onSubmit = vi.fn();
    render(<CurveSliderChallenge imageSrc={image} pieceSrc={piece} alt="Align curve" onSubmit={onSubmit} />);
    const slider = screen.getByRole('slider', { name: 'Align curve' });
    slider.focus();
    expect(document.activeElement).toBe(slider);

    fireEvent.keyDown(slider, { key: 'ArrowRight' });
    fireEvent.keyUp(slider, { key: 'ArrowRight' });
    expect(onSubmit).not.toHaveBeenCalled();
    fireEvent.keyDown(slider, { key: ' ' });
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });
});
