import { useState } from "react";
import { normalizePoint } from "../interaction";
import type { CaptchaPoint } from "../protocol";
import styles from "./SelectionChallenge.module.css";

export interface SelectionChallengeProps { imageSrc: string; width?: number; height?: number; label: string; disabled?: boolean; value?: CaptchaPoint; testId: string; onChange: (point: CaptchaPoint) => void; }

export function SelectionChallenge({ imageSrc, width = 400, height = 220, label, disabled, value, testId, onChange }: SelectionChallengeProps) {
  const [cursor, setCursor] = useState<CaptchaPoint>({ x: 5000, y: 5000 });
  const selectPointer = (event: React.MouseEvent<HTMLDivElement>) => {
    if (disabled) return;
    onChange(normalizePoint(event.clientX, event.clientY, event.currentTarget.getBoundingClientRect()));
  };
  const selectKeyboard = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (disabled) return;
    const step = event.shiftKey ? 1000 : 250;
    const movement: Record<string, CaptchaPoint> = { ArrowLeft: { x: -step, y: 0 }, ArrowRight: { x: step, y: 0 }, ArrowUp: { x: 0, y: -step }, ArrowDown: { x: 0, y: step } };
    if (movement[event.key]) {
      event.preventDefault();
      setCursor((current) => ({ x: Math.max(0, Math.min(10000, current.x + movement[event.key].x)), y: Math.max(0, Math.min(10000, current.y + movement[event.key].y)) }));
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onChange(cursor);
    }
  };
  return <div role="button" tabIndex={disabled ? -1 : 0} aria-label={label} aria-disabled={disabled} data-testid="captcha-surface" data-challenge-type={testId} className={styles.surface} style={{ aspectRatio: `${width} / ${height}` }} onClick={selectPointer} onKeyDown={selectKeyboard}>
    <img className={styles.image} src={imageSrc} alt="" draggable={false}/>
    {!value && <span className={styles.cursor} style={{ left: `${cursor.x / 100}%`, top: `${cursor.y / 100}%` }} aria-hidden="true"/>}
    {value && <span className={styles.marker} style={{ left: `${value.x / 100}%`, top: `${value.y / 100}%` }} aria-hidden="true">1</span>}
  </div>;
}
