import type { CSSProperties, PointerEvent as ReactPointerEvent } from 'react';
import { useRef, useState } from 'react';
import { MoveRight } from 'lucide-react';
import type { CaptchaTrackPoint } from '../protocol';
import { trackPoint } from '../interaction';
import styles from './ChallengeSlider.module.css';

export interface RotatePuzzleChallengeData { image: string; width?: number; height?: number; pieceSize?: number; initialAngle?: number; minDurationMs?: number }
export interface RotatePuzzleAnswer { angle: number; durationMs: number; track: CaptchaTrackPoint[] }
export interface RotatePuzzleChallengeProps { challenge: RotatePuzzleChallengeData; disabled?: boolean; label?: string; onChange?: (answer: RotatePuzzleAnswer) => void; onComplete: (answer: RotatePuzzleAnswer) => void }

const elapsed = (start: number) => Math.max(0, Math.round(performance.now() - start));
const normalize = (angle: number) => ((angle % 360) + 360) % 360;
const answerAngle = (angle: number) => normalize(Math.round(angle));

export function RotatePuzzleChallenge({ challenge, disabled, label = '拖动滑块使中心图像与背景对齐', onChange, onComplete }: RotatePuzzleChallengeProps) {
  const [value, setValue] = useState(0);
  const startedAt = useRef(performance.now());
  const activePointer = useRef<number>();
  const operation = useRef<CaptchaTrackPoint[]>([]);
  const completedDuration = () => Math.max(elapsed(startedAt.current), challenge.minDurationMs ?? 0);
  const initial = challenge.initialAngle ?? 180;
  const angleFor = (next: number) => normalize(initial + (next / 10000) * 360);
  const answer = (next = value): RotatePuzzleAnswer => ({
    angle: answerAngle(angleFor(next)),
    durationMs: elapsed(startedAt.current),
    track: operation.current,
  });
  const angle = angleFor(value);
  const width = challenge.width ?? 320;
  const height = challenge.height ?? 180;
  const stageStyle = {
    '--captcha-angle': `${angle}deg`,
    '--captcha-piece-size': `${challenge.pieceSize ?? 112}px`,
    '--captcha-image': `url("${challenge.image.replaceAll('"', '\\"')}")`,
    '--captcha-stage-width': `${width}px`,
    '--captcha-stage-height': `${height}px`,
    aspectRatio: `${width} / ${height}`,
  } as CSSProperties;

  const begin = (event: ReactPointerEvent<HTMLInputElement>) => {
    if (disabled) return;
    activePointer.current = event.pointerId;
    startedAt.current = performance.now();
    operation.current = [trackPoint({ x: value, y: 5000 }, 0, 'down')];
    event.currentTarget.setPointerCapture?.(event.pointerId);
  };
  const finish = (event: ReactPointerEvent<HTMLInputElement>) => {
    if (activePointer.current !== event.pointerId) return;
    const durationMs = completedDuration();
    operation.current = [...operation.current, trackPoint({ x: value, y: 5000 }, durationMs, 'up')];
    activePointer.current = undefined;
    onComplete({ ...answer(), durationMs });
  };

  return <div className={styles.challenge} data-testid="rotate-puzzle-challenge">
    <div className={styles.stage} style={stageStyle}><img className={styles.stageImage} src={challenge.image} alt="" draggable={false} /><span className={styles.piece} data-testid="rotate-piece" aria-hidden="true" /></div>
    <div className={styles.controls}><span className={styles.dragIcon} aria-hidden="true"><MoveRight size={25} /></span><input className={styles.range} aria-label={label} type="range" min={0} max={10000} step={1} value={value} disabled={disabled} style={{ '--captcha-progress': `${value / 100}%` } as CSSProperties} onPointerDown={begin} onChange={event => { const next = Number(event.currentTarget.value); setValue(next); const durationMs = elapsed(startedAt.current); if (activePointer.current !== undefined) operation.current.push(trackPoint({ x: next, y: 5000 }, durationMs, 'move')); onChange?.({ angle: answerAngle(angleFor(next)), durationMs, track: operation.current }); }} onPointerUp={finish} onPointerCancel={() => { activePointer.current = undefined; operation.current = []; }} onKeyDown={event => { if (!event.repeat && ['ArrowLeft', 'ArrowRight', 'Home', 'End', 'PageUp', 'PageDown'].includes(event.key)) { startedAt.current = performance.now(); operation.current = [trackPoint({ x: value, y: 5000 }, 0, 'down')]; } }} onKeyUp={event => { if (['ArrowLeft', 'ArrowRight', 'Home', 'End', 'PageUp', 'PageDown'].includes(event.key)) { const durationMs = completedDuration(); operation.current.push(trackPoint({ x: value, y: 5000 }, durationMs, 'up')); onComplete({ ...answer(), durationMs }); } }} /></div>
  </div>;
}
