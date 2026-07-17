import type { CSSProperties, PointerEvent as ReactPointerEvent } from 'react';
import { useRef, useState } from 'react';
import { MoveRight } from 'lucide-react';
import type { CaptchaTrackPoint } from '../protocol';
import { trackPoint } from '../interaction';
import styles from './ChallengeSlider.module.css';

export interface AngleChallengeData { image: string; initialAngle?: number; minDurationMs?: number }
export interface AngleChallengeAnswer { angle: number; durationMs: number; track: CaptchaTrackPoint[] }
export interface AngleChallengeProps { challenge: AngleChallengeData; disabled?: boolean; label?: string; onChange?: (answer: AngleChallengeAnswer) => void; onComplete: (answer: AngleChallengeAnswer) => void }
const duration = (start: number) => Math.max(0, Math.round(performance.now() - start));
const normalize = (angle: number) => ((angle % 360) + 360) % 360;
const answerAngle = (angle: number) => normalize(Math.round(angle));

export function AngleChallenge({ challenge, disabled, label = '拖动滑块使图片角度为正', onChange, onComplete }: AngleChallengeProps) {
  const [value, setValue] = useState(0);
  const started = useRef(performance.now());
  const pointer = useRef<number>();
  const operation = useRef<CaptchaTrackPoint[]>([]);
  const completedDuration = () => Math.max(duration(started.current), challenge.minDurationMs ?? 0);
  const initial = challenge.initialAngle ?? 180;
  const angleFor = (next: number) => normalize(initial + next / 10000 * 360);
  const angle = angleFor(value);
  const current = (next = value): AngleChallengeAnswer => ({ angle: answerAngle(angleFor(next)), durationMs: duration(started.current), track: operation.current });
  const begin = (event: ReactPointerEvent<HTMLInputElement>) => { if (disabled) return; pointer.current = event.pointerId; started.current = performance.now(); operation.current = [trackPoint({ x: value, y: 5000 }, 0, 'down')]; event.currentTarget.setPointerCapture?.(event.pointerId); };
  const finish = (event: ReactPointerEvent<HTMLInputElement>) => { if (pointer.current !== event.pointerId) return; const durationMs = completedDuration(); operation.current = [...operation.current, trackPoint({ x: value, y: 5000 }, durationMs, 'up')]; pointer.current = undefined; onComplete({ ...current(), durationMs }); };
  return <div className={styles.challenge} data-testid="angle-challenge">
    <div className={styles.roundStage} style={{ '--captcha-angle': `${angle}deg` } as CSSProperties}><img className={`${styles.stageImage} ${styles.rotatingImage}`} data-testid="angle-image" src={challenge.image} alt="" draggable={false} /></div>
    <div className={styles.controls}><span className={styles.dragIcon} aria-hidden="true"><MoveRight size={25} /></span><input className={styles.range} aria-label={label} type="range" min={0} max={10000} step={1} value={value} disabled={disabled} style={{ '--captcha-progress': `${value / 100}%` } as CSSProperties} onPointerDown={begin} onChange={event => { const next = Number(event.currentTarget.value); setValue(next); const durationMs = duration(started.current); if (pointer.current !== undefined) operation.current.push(trackPoint({ x: next, y: 5000 }, durationMs, 'move')); onChange?.({ angle: answerAngle(angleFor(next)), durationMs, track: operation.current }); }} onPointerUp={finish} onPointerCancel={() => { pointer.current = undefined; operation.current = []; }} onKeyDown={event => { if (!event.repeat && ['ArrowLeft', 'ArrowRight', 'Home', 'End', 'PageUp', 'PageDown'].includes(event.key)) { started.current = performance.now(); operation.current = [trackPoint({ x: value, y: 5000 }, 0, 'down')]; } }} onKeyUp={event => { if (['ArrowLeft', 'ArrowRight', 'Home', 'End', 'PageUp', 'PageDown'].includes(event.key)) { const durationMs = completedDuration(); operation.current.push(trackPoint({ x: value, y: 5000 }, durationMs, 'up')); onComplete({ ...current(), durationMs }); } }} /></div>
  </div>;
}
