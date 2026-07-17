import { useEffect, useRef, useState } from "react";
import { appendTrack, normalizePoint, trackPoint } from "../interaction";
import type { CaptchaResponse, CaptchaTrackPoint } from "../protocol";
import styles from "./ScratchChallenge.module.css";

const SCRATCH_BRUSH_DIAMETER = 36;

export interface ScratchChallengeProps { imageSrc: string; maskSrc: string; width?: number; height?: number; label: string; disabled?: boolean; startedAt: React.MutableRefObject<number>; onInteractionStart: () => void; onSubmit: (answer: Omit<CaptchaResponse, "token">) => void; }

export function ScratchChallenge({ imageSrc, maskSrc, width = 400, height = 220, label, disabled, startedAt, onInteractionStart, onSubmit }: ScratchChallengeProps) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const activePointer = useRef<number>();
  const trackRef = useRef<CaptchaTrackPoint[]>([]);
  const keyboardActive = useRef(false);
  const keyboardPoint = useRef({ x: 5000, y: 5000 });
  const [maskReady, setMaskReady] = useState(false);
  useEffect(() => {
    setMaskReady(false);
    const image = new Image();
    image.onload = () => {
      const context = canvas.current?.getContext("2d");
      if (!context) return;
      context.globalCompositeOperation = "source-over";
      context.clearRect(0, 0, width, height);
      context.drawImage(image, 0, 0, width, height);
      setMaskReady(true);
    };
    image.src = maskSrc;
    return () => { image.onload = null; };
  }, [height, maskSrc, width]);
  const eraseSegment = (from: { x: number; y: number }, to: { x: number; y: number }) => {
    const context = canvas.current?.getContext("2d");
    if (!context) return;
    context.globalCompositeOperation = "destination-out";
    context.lineCap = "round";
    context.lineJoin = "round";
    context.lineWidth = SCRATCH_BRUSH_DIAMETER;
    context.beginPath();
    context.moveTo((from.x / 10000) * width, (from.y / 10000) * height);
    context.lineTo((to.x / 10000) * width, (to.y / 10000) * height);
    context.stroke();
  };
  const append = (event: React.PointerEvent, type: "down" | "move" | "up") => {
    const point = normalizePoint(event.clientX, event.clientY, event.currentTarget.getBoundingClientRect());
    const next = appendTrack(trackRef.current, trackPoint(point, performance.now() - startedAt.current, type));
    const previous = trackRef.current.at(-1);
    trackRef.current = next;
    if (previous) eraseSegment(previous, point);
    return next;
  };
  const pointerDown = (event: React.PointerEvent<HTMLDivElement>) => {
    if (disabled || !maskReady) return;
    activePointer.current = event.pointerId;
    trackRef.current = [];
    event.currentTarget.setPointerCapture?.(event.pointerId);
    onInteractionStart();
    append(event, "down");
  };
  const pointerMove = (event: React.PointerEvent<HTMLDivElement>) => { if (activePointer.current === event.pointerId) append(event, "move"); };
  const pointerUp = (event: React.PointerEvent<HTMLDivElement>) => {
    if (activePointer.current !== event.pointerId) return;
    const track = append(event, "up");
    activePointer.current = undefined;
    onSubmit({ track, duration_ms: Math.round(performance.now() - startedAt.current) });
  };
  const pointerCancel = (event: React.PointerEvent<HTMLDivElement>) => { if (activePointer.current === event.pointerId) { activePointer.current = undefined; trackRef.current = []; } };
  const keyboardTrackPoint = (type: "down" | "move" | "up") => {
    const next = appendTrack(trackRef.current, trackPoint(keyboardPoint.current, performance.now() - startedAt.current, type));
    const previous = trackRef.current.at(-1);
    trackRef.current = next;
    if (previous) eraseSegment(previous, keyboardPoint.current);
    return next;
  };
  const keyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (disabled || !maskReady) return;
    if (event.key === " " && !keyboardActive.current) {
      event.preventDefault();
      keyboardActive.current = true;
      trackRef.current = [];
      onInteractionStart();
      keyboardTrackPoint("down");
      return;
    }
    if (event.key === "Escape") { keyboardActive.current = false; trackRef.current = []; return; }
    if (!keyboardActive.current) return;
    const step = event.shiftKey ? 1000 : 400;
    const movement: Record<string, { x: number; y: number }> = { ArrowLeft: { x: -step, y: 0 }, ArrowRight: { x: step, y: 0 }, ArrowUp: { x: 0, y: -step }, ArrowDown: { x: 0, y: step } };
    if (movement[event.key]) {
      event.preventDefault();
      keyboardPoint.current = { x: Math.max(0, Math.min(10000, keyboardPoint.current.x + movement[event.key].x)), y: Math.max(0, Math.min(10000, keyboardPoint.current.y + movement[event.key].y)) };
      keyboardTrackPoint("move");
    } else if (event.key === "Enter") {
      event.preventDefault();
      keyboardActive.current = false;
      const track = keyboardTrackPoint("up");
      onSubmit({ track, duration_ms: Math.round(performance.now() - startedAt.current) });
    }
  };
  return <div role="application" tabIndex={disabled ? -1 : 0} aria-label={label} aria-disabled={disabled || !maskReady} data-testid="scratch-challenge" className={styles.surface} style={{ aspectRatio: `${width} / ${height}` }} onPointerDown={pointerDown} onPointerMove={pointerMove} onPointerUp={pointerUp} onPointerCancel={pointerCancel} onKeyDown={keyDown}>
    <img className={styles.image} src={imageSrc} alt="" draggable={false}/>
    <canvas ref={canvas} className={styles.mask} width={width} height={height} aria-hidden="true"/>
  </div>;
}
