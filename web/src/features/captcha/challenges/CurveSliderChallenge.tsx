import {
  useRef,
  useState,
  type ChangeEvent,
  type CSSProperties,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from 'react';
import { MoveRight } from 'lucide-react';
import { clampCoordinate, trackPoint } from '../interaction';
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

export function CurveSliderChallenge({
  imageSrc,
  pieceSrc,
  minDurationMs = 0,
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

  const completeOperation = (finalValue: number) => {
    const duration = Math.max(
      minDurationMs,
      Math.max(0, Math.round(performance.now() - startedAt.current)),
    );
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
      valueTrack.current.push(trackPoint({ x: next, y: 5_000 }, performance.now() - startedAt.current, 'move'));
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

  const adjustmentKeys = new Set([
    'ArrowLeft',
    'ArrowRight',
    'ArrowUp',
    'ArrowDown',
    'Home',
    'End',
    'PageUp',
    'PageDown',
  ]);

  const beginKeyboard = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (
      disabled ||
      !adjustmentKeys.has(event.key) ||
      event.repeat ||
      keyboardActive.current ||
      activePointer.current !== null
    ) return;
    keyboardActive.current = true;
    startOperation();
  };

  const finishKeyboard = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (disabled || !adjustmentKeys.has(event.key) || !keyboardActive.current) return;
    const finalValue = clampCoordinate(event.currentTarget.valueAsNumber);
    valueRef.current = finalValue;
    setValue(finalValue);
    completeOperation(finalValue);
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
          onKeyDown={beginKeyboard}
          onKeyUp={finishKeyboard}
          onBlur={() => {
            if (keyboardActive.current) clearOperation(true);
          }}
        />
      </div>
    </div>
  );
}
