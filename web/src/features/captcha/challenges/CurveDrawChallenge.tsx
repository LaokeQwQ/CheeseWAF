import { useCallback, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import { appendTrack, normalizePoint, trackPoint } from '../interaction';
import type { CaptchaResponse, CaptchaTrackPoint } from '../protocol';
import styles from './CurveDrawChallenge.module.css';

export interface CurveDrawChallengeProps {
  imageSrc: string;
  disabled?: boolean;
  className?: string;
  alt?: string;
  onInteractionStart?: () => void;
  onSubmit: (response: Omit<CaptchaResponse, 'token'>) => void | Promise<void>;
}

type DisplayPoint = { x: number; y: number };

export function CurveDrawChallenge({ imageSrc, disabled = false, className, alt = '', onInteractionStart, onSubmit }: CurveDrawChallengeProps) {
  const [displayPoints, setDisplayPoints] = useState<DisplayPoint[]>([]);
  const activePointer = useRef<number | null>(null);
  const startedAt = useRef(0);
  const track = useRef<CaptchaTrackPoint[]>([]);

  const capture = useCallback((event: ReactPointerEvent<HTMLDivElement>, type: 'down' | 'move' | 'up') => {
    const rect = event.currentTarget.getBoundingClientRect();
    const point = normalizePoint(event.clientX, event.clientY, rect);
    const elapsed = Math.max(0, performance.now() - startedAt.current);
    track.current = appendTrack(track.current, trackPoint(point, elapsed, type), 256);
    setDisplayPoints((current) => [...current, { x: point.x / 100, y: point.y / 100 }].slice(-256));
  }, []);

  const handlePointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (disabled || activePointer.current !== null) return;
    activePointer.current = event.pointerId;
    startedAt.current = performance.now();
    track.current = [];
    setDisplayPoints([]);
    event.currentTarget.setPointerCapture?.(event.pointerId);
    capture(event, 'down');
    onInteractionStart?.();
  };

  const handlePointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (activePointer.current !== event.pointerId) return;
    capture(event, 'move');
  };

  const finish = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (activePointer.current !== event.pointerId) return;
    capture(event, 'up');
    const duration = Math.max(0, Math.round(performance.now() - startedAt.current));
    const answer = { track: track.current, duration_ms: duration };
    activePointer.current = null;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
    if (answer.track.length >= 2) void onSubmit(answer);
  };

  const cancel = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (activePointer.current !== event.pointerId) return;
    activePointer.current = null;
    track.current = [];
    setDisplayPoints([]);
    event.currentTarget.releasePointerCapture?.(event.pointerId);
  };

  const polyline = displayPoints.map((point) => `${point.x},${point.y}`).join(' ');

  return (
    <div
      className={`${styles.surface} ${disabled ? styles.disabled : ''} ${className ?? ''}`}
      data-testid="curve-draw-surface"
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={finish}
      onPointerCancel={cancel}
      role="application"
      aria-disabled={disabled}
    >
      <img className={styles.image} src={imageSrc} alt={alt} draggable={false} />
      <svg className={styles.ink} viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
        {polyline && <polyline points={polyline} className={styles.stroke} vectorEffect="non-scaling-stroke" />}
      </svg>
    </div>
  );
}
