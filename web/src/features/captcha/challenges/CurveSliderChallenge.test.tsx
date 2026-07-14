import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CurveSliderChallenge } from './CurveSliderChallenge';

const image = 'data:image/png;base64,iVBORw0KGgo=';
const piece = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

afterEach(cleanup);

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

  it('records one keyboard transaction and honors the issued minimum duration', () => {
    const onSubmit = vi.fn();
    render(
      <CurveSliderChallenge
        imageSrc={image}
        pieceSrc={piece}
        minDurationMs={450}
        alt="Align curve"
        onSubmit={onSubmit}
      />,
    );
    const slider = screen.getByRole('slider', { name: 'Align curve' });
    fireEvent.keyDown(slider, { key: 'End' });
    fireEvent.change(slider, { target: { value: '10000' } });
    fireEvent.keyUp(slider, { key: 'End' });
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({
      point: { x: 10000, y: 5000 },
      duration_ms: 450,
      track: [
        expect.objectContaining({ x: 5000, type: 'down' }),
        expect.objectContaining({ x: 10000, type: 'move' }),
        expect.objectContaining({ x: 10000, type: 'up', t: 450 }),
      ],
    }));
  });
});
