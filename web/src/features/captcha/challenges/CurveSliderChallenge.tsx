import {
  useRef,
  useState,
  type ChangeEvent,
  type CSSProperties,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from 'react';
import { MoveRight } from 'lucide-react';
import { appendTrack, clampCoordinate, trackPoint } from '../interaction';
import type { CaptchaResponse, CaptchaTrackPoint } from '../protocol';
import styles from './CurveSliderChallenge.module.css';
import { curveSliderOffsetPercent } from './curveSliderFormula';

export interface CurveSliderChallengeProps {
  imageSrc: string;
  pieceSrc?: string;
  minDurationMs?: number;
  disabled?: boolean;
  className?: string;
  alt?: string;
  initialValue?: number;
  onInteractionStart?: () => void;
  onSubmit: (response: Omit<CaptchaResponse, 'token'>) => void | Promise<void>;
}

const ADJUSTMENT_KEYS = new Set([
  'ArrowLeft',
  'ArrowRight',
  'ArrowUp',
  'ArrowDown',
  'Home',
  'End',
  'PageUp',
  'PageDown',
]);
const KEYBOARD_FINE_STEP = 100;
const KEYBOARD_COARSE_STEP = 1_000;
const KEYBOARD_TRAIL_STEP = 250;
const MAX_TRACK_POINTS = 128;

export function CurveSliderChallenge({
  imageSrc,
  pieceSrc,
  minDurationMs,
  disabled = false,
  className,
  alt = '',
  initialValue = 5_000,
  onInteractionStart,
  onSubmit,
}: CurveSliderChallengeProps) {
  const [value, setValue] = useState(() => clampCoordinate(initialValue));
  const valueRef = useRef(value);
  const startedAt = useRef(0);
  const activePointer = useRef<number | null>(null);
  const keyboardActive = useRef(false);
  const operationStartValue = useRef(value);
  const valueTrack = useRef<CaptchaTrackPoint[]>([]);
  const offset = curveSliderOffsetPercent(value);

  const startOperation = () => {
    startedAt.current = performance.now();
    operationStartValue.current = valueRef.current;
    valueTrack.current = [trackPoint({ x: valueRef.current, y: 5_000 }, 0, 'down')];
    onInteractionStart?.();
  };

  const clearOperation = (restore = false) => {
    activePointer.current = null;
    keyboardActive.current = false;
    valueTrack.current = [];
    if (restore) {
      valueRef.current = operationStartValue.current;
      setValue(operationStartValue.current);
    }
  };

  const elapsedMs = () => Math.max(0, Math.round(performance.now() - startedAt.current));
  const completedDuration = () => Math.max(elapsedMs(), minDurationMs ?? 0);

  const appendMove = (next: number) => {
    valueTrack.current = appendTrack(
      valueTrack.current,
      trackPoint({ x: next, y: 5_000 }, elapsedMs(), 'move'),
      MAX_TRACK_POINTS - 1,
    );
  };

  const completeOperation = (finalValue: number) => {
    const duration = completedDuration();
    const operation = [
      ...valueTrack.current,
      trackPoint({ x: finalValue, y: 5_000 }, duration, 'up'),
    ];
    clearOperation();
    void onSubmit({
      point: { x: finalValue, y: 5_000 },
      track: operation,
      duration_ms: duration,
    });
  };

  const begin = (event: ReactPointerEvent<HTMLInputElement>) => {
    if (disabled || activePointer.current !== null || keyboardActive.current) return;
    activePointer.current = event.pointerId;
    startOperation();
    event.currentTarget.setPointerCapture?.(event.pointerId);
  };

  const change = (event: ChangeEvent<HTMLInputElement>) => {
    const next = clampCoordinate(Number(event.target.value));
    valueRef.current = next;
    setValue(next);
    if (activePointer.current !== null || keyboardActive.current) {
      appendMove(next);
    }
  };

  const finish = (event: ReactPointerEvent<HTMLInputElement>) => {
    if (disabled || activePointer.current !== event.pointerId) return;
    const finalValue = clampCoordinate(event.currentTarget.valueAsNumber);
    valueRef.current = finalValue;
    setValue(finalValue);
    activePointer.current = null;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
    completeOperation(finalValue);
  };

  const cancel = (event: ReactPointerEvent<HTMLInputElement>) => {
    if (activePointer.current !== event.pointerId) return;
    activePointer.current = null;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
    clearOperation(true);
  };

  const nextKeyboardValue = (key: string) => {
    switch (key) {
      case 'ArrowLeft':
      case 'ArrowDown':
        return valueRef.current - KEYBOARD_FINE_STEP;
      case 'ArrowRight':
      case 'ArrowUp':
        return valueRef.current + KEYBOARD_FINE_STEP;
      case 'PageDown':
        return valueRef.current - KEYBOARD_COARSE_STEP;
      case 'PageUp':
        return valueRef.current + KEYBOARD_COARSE_STEP;
      case 'Home':
        return 0;
      case 'End':
        return 10_000;
      default:
        return valueRef.current;
    }
  };

  const adjustKeyboard = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (disabled || !ADJUSTMENT_KEYS.has(event.key) || activePointer.current !== null) return;
    event.preventDefault();
    const next = clampCoordinate(nextKeyboardValue(event.key));
    if (next === valueRef.current) return;
    if (!keyboardActive.current) {
      keyboardActive.current = true;
      startOperation();
    }

    const start = valueRef.current;
    const steps = Math.max(2, Math.ceil(Math.abs(next - start) / KEYBOARD_TRAIL_STEP));
    for (let step = 1; step <= steps; step += 1) {
      appendMove(clampCoordinate(start + ((next - start) * step) / steps));
    }
    valueRef.current = next;
    setValue(next);
  };

  const submitKeyboard = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (disabled || !keyboardActive.current || (event.key !== 'Enter' && event.key !== ' ')) return;
    event.preventDefault();
    completeOperation(valueRef.current);
  };

  const pieceStyle = { '--captcha-offset': `${offset}%` } as CSSProperties;

  return (
    <div className={`${styles.challenge} ${className ?? ''}`}>
      <div className={styles.stage}>
        <img className={styles.image} src={imageSrc} alt={alt} draggable={false} />
        {pieceSrc ? (
          <img
            className={styles.piece}
            data-testid="curve-slider-piece"
            data-offset={offset}
            src={pieceSrc}
            alt=""
            draggable={false}
            style={pieceStyle}
          />
        ) : null}
      </div>
      <div className={styles.controlRow}>
        <span className={styles.dragMark} aria-hidden="true">
          <MoveRight size={22} />
        </span>
        <input
          className={styles.range}
          type="range"
          min="0"
          max="10000"
          step="1"
          value={value}
          disabled={disabled}
          aria-label={alt}
          data-testid="curve-slider-control"
          data-progress={value}
          style={{ '--captcha-progress': `${value / 100}%` } as CSSProperties}
          onPointerDown={begin}
          onChange={change}
          onPointerUp={finish}
          onPointerCancel={cancel}
          onLostPointerCapture={cancel}
          onKeyDown={(event) => {
            adjustKeyboard(event);
            submitKeyboard(event);
          }}
          onBlur={() => {
            if (keyboardActive.current) clearOperation(true);
          }}
        />
      </div>
    </div>
  );
}
