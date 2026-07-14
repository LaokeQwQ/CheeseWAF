import { useMemo, useRef, useState, type ChangeEvent, type PointerEvent as ReactPointerEvent } from 'react';
import { clampCoordinate, trackPoint } from '../interaction';
import type { CaptchaPoint, CaptchaResponse, CaptchaTrackPoint } from '../protocol';
import styles from './CurveSliderChallenge.module.css';
import { curveSliderPoints } from './curveSliderFormula';

export interface CurveSliderChallengeProps {
  imageSrc: string;
  version?: number;
  disabled?: boolean;
  className?: string;
  alt?: string;
  initialValue?: number;
  onInteractionStart?: () => void;
  onSubmit: (response: Omit<CaptchaResponse, 'token'>) => void | Promise<void>;
}

function toPath(points: CaptchaPoint[]) {
  return points.map((point, index) => `${index ? 'L' : 'M'} ${point.x / 100} ${point.y / 100}`).join(' ');
}

export function CurveSliderChallenge({ imageSrc, version = 1, disabled = false, className, alt = '', initialValue = 0, onInteractionStart, onSubmit }: CurveSliderChallengeProps) {
  const [value, setValue] = useState(() => clampCoordinate(initialValue));
  const startedAt = useRef(0);
  const activePointer = useRef<number | null>(null);
  const valueTrack = useRef<CaptchaTrackPoint[]>([]);
  const curve = useMemo(() => curveSliderPoints(value, version), [value, version]);

  const begin = (event: ReactPointerEvent<HTMLInputElement>) => {
    if (disabled || activePointer.current !== null) return;
    activePointer.current = event.pointerId;
    startedAt.current = performance.now();
    valueTrack.current = [trackPoint({ x: value, y: 5_000 }, 0, 'down')];
    event.currentTarget.setPointerCapture?.(event.pointerId);
    onInteractionStart?.();
  };

  const change = (event: ChangeEvent<HTMLInputElement>) => {
    const next = clampCoordinate(Number(event.target.value));
    setValue(next);
    if (activePointer.current !== null) {
      valueTrack.current.push(trackPoint({ x: next, y: 5_000 }, performance.now() - startedAt.current, 'move'));
    }
  };

  const finish = (event: ReactPointerEvent<HTMLInputElement>) => {
    if (disabled || activePointer.current !== event.pointerId) return;
    const duration = Math.max(0, Math.round(performance.now() - startedAt.current));
    const operation = [...valueTrack.current, trackPoint({ x: value, y: 5_000 }, duration, 'up')];
    activePointer.current = null;
    valueTrack.current = [];
    event.currentTarget.releasePointerCapture?.(event.pointerId);
    void onSubmit({ point: { x: value, y: 5_000 }, track: operation, duration_ms: duration });
  };

  const cancel = (event: ReactPointerEvent<HTMLInputElement>) => {
    if (activePointer.current !== event.pointerId) return;
    activePointer.current = null;
    valueTrack.current = [];
    event.currentTarget.releasePointerCapture?.(event.pointerId);
  };

  return (
    <div className={`${styles.challenge} ${className ?? ''}`}>
      <div className={styles.stage}>
        <img className={styles.image} src={imageSrc} alt={alt} draggable={false} />
        <svg className={styles.curveLayer} viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
          <path data-testid="curve-slider-foreground" data-progress={value} d={toPath(curve)} className={styles.foreground} vectorEffect="non-scaling-stroke" />
          <circle cx={curve[0].x / 100} cy={curve[0].y / 100} r="2.2" className={styles.endpoint} vectorEffect="non-scaling-stroke" />
          <circle cx={curve.at(-1)!.x / 100} cy={curve.at(-1)!.y / 100} r="2.2" className={styles.endpoint} vectorEffect="non-scaling-stroke" />
        </svg>
      </div>
      <div className={styles.controlRow}>
        <span className={styles.dragMark} aria-hidden="true">···›</span>
        <input
          className={styles.range}
          type="range"
          min="0"
          max="10000"
          step="25"
          value={value}
          disabled={disabled}
          aria-label="Curve alignment"
          onPointerDown={begin}
          onChange={change}
          onPointerUp={finish}
          onPointerCancel={cancel}
        />
      </div>
    </div>
  );
}
