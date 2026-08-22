import { useCallback, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent } from 'react';
import { DEFAULT_TRACK_LIMIT, appendTrack, normalizePoint, trackPoint } from '../interaction';
import type { CaptchaResponse, CaptchaTrackPoint } from '../protocol';
import styles from './CurveDrawChallenge.module.css';

export interface CurveDrawChallengeProps {
  imageSrc: string;
  disabled?: boolean;
  className?: string;
  alt?: string;
  label?: string;
  minDurationMs?: number;
  onInteractionStart?: () => void;
  onSubmit: (response: Omit<CaptchaResponse, 'token'>) => void | Promise<void>;
}

type DisplayPoint = { x: number; y: number };

export function CurveDrawChallenge({
  imageSrc,
  disabled = false,
  className,
  alt = '',
  label,
  onInteractionStart,
  minDurationMs,
  onSubmit,
}: CurveDrawChallengeProps) {
  const [displayPoints, setDisplayPoints] = useState<DisplayPoint[]>([]);
  const activePointer = useRef<number | null>(null);
  const startedAt = useRef(0);
  const track = useRef<CaptchaTrackPoint[]>([]);
  const keyboardActive = useRef(false);
  const keyboardPoint = useRef({ x: 5000, y: 5000 });
  const surfaceLabel = label || alt || 'curve draw challenge';

  const capture = useCallback((event: ReactPointerEvent<HTMLDivElement>, type: 'down' | 'move' | 'up') => {
    const rect = event.currentTarget.getBoundingClientRect();
    const point = normalizePoint(event.clientX, event.clientY, rect);
    const elapsed = Math.max(0, performance.now() - startedAt.current);
    track.current = appendTrack(track.current, trackPoint(point, elapsed, type), DEFAULT_TRACK_LIMIT);
    setDisplayPoints((current) => [...current, { x: point.x / 100, y: point.y / 100 }].slice(-DEFAULT_TRACK_LIMIT));
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
    const duration = Math.max(minDurationMs ?? 0, Math.round(performance.now() - startedAt.current));
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

  const keyboardTrackPoint = (type: 'down' | 'move' | 'up') => {
    const elapsed = Math.max(0, performance.now() - startedAt.current);
    track.current = appendTrack(track.current, trackPoint(keyboardPoint.current, elapsed, type), DEFAULT_TRACK_LIMIT);
    setDisplayPoints((current) => [...current, { x: keyboardPoint.current.x / 100, y: keyboardPoint.current.y / 100 }].slice(-DEFAULT_TRACK_LIMIT));
    return track.current;
  };

  const keyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (disabled) return;
    if (event.key === ' ' && !keyboardActive.current) {
      event.preventDefault();
      keyboardActive.current = true;
      startedAt.current = performance.now();
      track.current = [];
      setDisplayPoints([]);
      keyboardTrackPoint('down');
      onInteractionStart?.();
      return;
    }
    if (event.key === 'Escape') {
      keyboardActive.current = false;
      track.current = [];
      setDisplayPoints([]);
      return;
    }
    if (!keyboardActive.current) return;
    const movement: Record<string, { x: number; y: number }> = {
      ArrowLeft: { x: -300, y: 0 },
      ArrowRight: { x: 300, y: 0 },
      ArrowUp: { x: 0, y: -300 },
      ArrowDown: { x: 0, y: 300 },
    };
    if (movement[event.key]) {
      event.preventDefault();
      keyboardPoint.current = {
        x: Math.max(0, Math.min(10000, keyboardPoint.current.x + movement[event.key].x)),
        y: Math.max(0, Math.min(10000, keyboardPoint.current.y + movement[event.key].y)),
      };
      keyboardTrackPoint('move');
    }
    if (event.key === 'Enter') {
      event.preventDefault();
      keyboardActive.current = false;
      const next = keyboardTrackPoint('up');
      if (next.length >= 2) {
        void onSubmit({ track: next, duration_ms: Math.max(minDurationMs ?? 0, Math.round(performance.now() - startedAt.current)) });
      }
    }
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
      onKeyDown={keyDown}
      role="application"
      tabIndex={disabled ? -1 : 0}
      aria-label={surfaceLabel}
      aria-disabled={disabled}
    >
      <img className={styles.image} src={imageSrc} alt={alt} draggable={false} />
      <svg className={styles.ink} viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
        {polyline && <polyline points={polyline} className={styles.stroke} vectorEffect="non-scaling-stroke" />}
      </svg>
    </div>
  );
}
