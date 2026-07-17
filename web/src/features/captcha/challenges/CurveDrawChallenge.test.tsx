import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CurveDrawChallenge } from './CurveDrawChallenge';

const image = 'data:image/png;base64,iVBORw0KGgo=';

function setRect(element: HTMLElement) {
  vi.spyOn(element, 'getBoundingClientRect').mockReturnValue({ left: 10, top: 20, width: 300, height: 150, right: 310, bottom: 170, x: 10, y: 20, toJSON: () => ({}) });
}

afterEach(cleanup);

describe('CurveDrawChallenge', () => {
  it('submits a normalized pointer track on release', () => {
    const onSubmit = vi.fn();
    render(<CurveDrawChallenge imageSrc={image} onSubmit={onSubmit} />);
    const surface = screen.getByTestId('curve-draw-surface');
    setRect(surface);
    fireEvent.pointerDown(surface, { pointerId: 7, clientX: 40, clientY: 50 });
    fireEvent.pointerMove(surface, { pointerId: 7, clientX: 160, clientY: 95 });
    fireEvent.pointerUp(surface, { pointerId: 7, clientX: 280, clientY: 140 });
    expect(onSubmit).toHaveBeenCalledTimes(1);
    const response = onSubmit.mock.calls[0][0];
    expect(response.track[0]).toMatchObject({ x: 1000, y: 2000, type: 'down' });
    expect(response.track.at(-1)).toMatchObject({ x: 9000, y: 8000, type: 'up' });
    expect(response.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('does not submit a cancelled gesture', () => {
    const onSubmit = vi.fn();
    render(<CurveDrawChallenge imageSrc={image} onSubmit={onSubmit} />);
    const surface = screen.getByTestId('curve-draw-surface');
    setRect(surface);
    fireEvent.pointerDown(surface, { pointerId: 3, clientX: 40, clientY: 50 });
    fireEvent.pointerCancel(surface, { pointerId: 3 });
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
