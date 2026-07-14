import { useCallback, useEffect, useRef, useState } from "react";
import type { CaptchaLocale } from "./i18n";
import { captchaText } from "./i18n";
import {
  appendTrack,
  normalizePoint,
  solvePow,
  trackPoint,
} from "./interaction";
import type {
  CaptchaChallenge,
  CaptchaPoint,
  CaptchaResponse,
  CaptchaTrackPoint,
  CaptchaType,
  CaptchaVerifyResult,
  IssueCaptcha,
  VerifyCaptcha,
} from "./protocol";
import { safeImageDataUri } from "./protocol";
import { CaptchaShell } from "./CaptchaShell";
import { AngleChallenge } from "./challenges/AngleChallenge";
import { CurveDrawChallenge } from "./challenges/CurveDrawChallenge";
import { CurveSliderChallenge } from "./challenges/CurveSliderChallenge";
import { RestoreSliderChallenge } from "./challenges/RestoreSliderChallenge";
import { RotatePuzzleChallenge } from "./challenges/RotatePuzzleChallenge";
import { TextClickChallenge } from "./challenges/TextClickChallenge";
import { IconClickChallenge } from "./challenges/IconClickChallenge";
import { ScratchChallenge } from "./challenges/ScratchChallenge";
import sliderStyles from "./challenges/ChallengeSlider.module.css";
import styles from "./BehaviorCaptcha.module.css";

export interface BehaviorCaptchaProps {
  type: CaptchaType;
  issue: IssueCaptcha;
  verify: VerifyCaptcha;
  locale?: CaptchaLocale;
  disabled?: boolean;
  className?: string;
  logoSrc?: string;
  onClose?: () => void;
  onVerified?: (result: CaptchaVerifyResult & { valid: true }) => void;
  onStatusChange?: (status: CaptchaStatus) => void;
}
export type CaptchaStatus =
  | "loading"
  | "ready"
  | "interacting"
  | "verifying"
  | "success"
  | "failure"
  | "error";

export function BehaviorCaptcha({
  type,
  issue,
  verify,
  locale = "zh-CN",
  disabled,
  className,
  logoSrc,
  onClose,
  onVerified,
  onStatusChange,
}: BehaviorCaptchaProps) {
  const [challenge, setChallenge] = useState<CaptchaChallenge>();
  const [status, setStatus] = useState<CaptchaStatus>("loading");
  const [message, setMessage] = useState("");
  const [generation, setGeneration] = useState(0);
  const [response, setResponse] = useState<Omit<CaptchaResponse, "token">>({});
  const started = useRef(performance.now());
  const submitLock = useRef(false);
  const requestSequence = useRef(0);
  const verifySequence = useRef(0);
  const activeToken = useRef("");
  const issueController = useRef<AbortController>();
  const verifyController = useRef<AbortController>();
  const retryTimer = useRef<number>();
  const changeStatus = useCallback(
    (next: CaptchaStatus) => {
      setStatus(next);
      onStatusChange?.(next);
    },
    [onStatusChange],
  );
  const refresh = useCallback(() => {
    window.clearTimeout(retryTimer.current);
    issueController.current?.abort();
    verifyController.current?.abort();
    requestSequence.current += 1;
    verifySequence.current += 1;
    activeToken.current = "";
    submitLock.current = false;
    setGeneration((value) => value + 1);
  }, []);
  const close = useCallback(() => {
    window.clearTimeout(retryTimer.current);
    issueController.current?.abort();
    verifyController.current?.abort();
    requestSequence.current += 1;
    verifySequence.current += 1;
    activeToken.current = String();
    submitLock.current = false;
    onClose?.();
  }, [onClose]);
  useEffect(() => {
    const sequence = ++requestSequence.current;
    const controller = new AbortController();
    issueController.current?.abort();
    issueController.current = controller;
    activeToken.current = "";
    submitLock.current = false;
    setChallenge(undefined);
    changeStatus("loading");
    setResponse({});
    setMessage(captchaText(locale, "loading"));
    abortable(issue(type, controller.signal), controller.signal)
      .then((value) => {
        if (controller.signal.aborted || sequence !== requestSequence.current) return;
        activeToken.current = value.token;
        setChallenge(value);
        started.current = performance.now();
        setMessage("");
        changeStatus("ready");
      })
      .catch((error) => {
        if (!isAbortError(error) && sequence === requestSequence.current) {
          setMessage(captchaText(locale, "error"));
          changeStatus("error");
        }
      });
    return () => {
      controller.abort();
      if (issueController.current === controller) issueController.current = undefined;
      requestSequence.current += 1;
      verifySequence.current += 1;
      activeToken.current = "";
      window.clearTimeout(retryTimer.current);
      verifyController.current?.abort();
    };
  }, [type, generation, issue, locale, changeStatus]);
  const submit = useCallback(
    async (answer = response) => {
      if (
        !challenge ||
        disabled ||
        submitLock.current ||
        status === "success" ||
        status === "failure" ||
        status === "error"
      )
        return;
      submitLock.current = true;
      const token = challenge.token;
      const sequence = ++verifySequence.current;
      const controller = new AbortController();
      verifyController.current?.abort();
      verifyController.current = controller;
      changeStatus("verifying");
      setMessage(captchaText(locale, "verifying"));
      try {
        const result = await abortable(verify({ token, ...answer }, controller.signal), controller.signal);
        if (controller.signal.aborted || sequence !== verifySequence.current || activeToken.current !== token) return;
        if (result.valid) {
          changeStatus("success");
          setMessage(captchaText(locale, "success"));
          onVerified?.(result as CaptchaVerifyResult & { valid: true });
          return;
        }
        changeStatus("failure");
        setMessage(captchaText(locale, "failed"));
        retryTimer.current = window.setTimeout(refresh, 1000);
      } catch (error) {
        if (!isAbortError(error) && sequence === verifySequence.current && activeToken.current === token) {
          changeStatus("error");
          setMessage(captchaText(locale, "error"));
        }
      } finally {
        if (sequence === verifySequence.current && activeToken.current === token) {
          submitLock.current = false;
          if (verifyController.current === controller) verifyController.current = undefined;
        }
      }
    },
    [
      challenge,
      disabled,
      locale,
      onVerified,
      refresh,
      response,
      status,
      verify,
      changeStatus,
    ],
  );
  const title = challenge
    ? challengeTypeTitle(challenge.type, locale)
    : captchaText(locale, "loading");
  const prompt = challenge
    ? localizedPrompt(challenge, locale)
    : captchaText(locale, "loading");
  const frozen = Boolean(
    disabled ||
    status === "loading" ||
    status === "verifying" ||
    status === "success" ||
    status === "failure" ||
    status === "error",
  );
  return (
    <CaptchaShell
      title={title}
      prompt={prompt}
      locale={locale}
      status={status}
      message={message}
      logoSrc={logoSrc}
      className={className}
      refreshDisabled={Boolean(disabled || status === "success")}
      onRefresh={refresh}
      onClose={onClose ? close : undefined}
    >
      {challenge && (
        <ChallengeBody
          key={challenge.token}
          challenge={challenge}
          locale={locale}
          disabled={frozen}
          started={started}
          response={response}
          setResponse={setResponse}
          setStatus={changeStatus}
          submit={submit}
        />
      )}
      {challenge &&
        challenge.type !== "pow" &&
        challenge.type !== "curve_draw" &&
        challenge.type !== "curve_slider" &&
        challenge.type !== "shape_slider" &&
        challenge.type !== "restore_slider" &&
        challenge.type !== "angle" &&
        challenge.type !== "rotate" &&
        challenge.type !== "scratch" && (
          <button
            type="button"
            className={styles.primary}
            disabled={frozen || !readyResponse(challenge, response)}
            onClick={() => void submit()}
          >
            {status === "verifying"
              ? captchaText(locale, "verifying")
              : captchaText(locale, "verify")}
          </button>
        )}
    </CaptchaShell>
  );
}

type BodyProps = {
  challenge: CaptchaChallenge;
  locale: CaptchaLocale;
  disabled?: boolean;
  started: React.MutableRefObject<number>;
  response: Omit<CaptchaResponse, "token">;
  setResponse: (value: Omit<CaptchaResponse, "token">) => void;
  setStatus: (status: CaptchaStatus) => void;
  submit: (answer?: Omit<CaptchaResponse, "token">) => Promise<void>;
};
function ChallengeBody(props: BodyProps) {
  const { challenge, disabled, locale, setStatus, submit } = props;
  const image = safeImageDataUri(challenge.presentation.image);
  if (challenge.type === "pow") return <PowBody {...props} />;
  if (!image)
    return (
      <SafeImage
        src={challenge.presentation.image}
        alt={localizedPrompt(challenge, locale)}
      />
    );
  if (challenge.type === "text_click" || challenge.type === "icon_click") {
    const Selection = challenge.type === "text_click" ? TextClickChallenge : IconClickChallenge;
    return <Selection imageSrc={image} width={challenge.presentation.width} height={challenge.presentation.height} label={localizedPrompt(challenge, locale)} disabled={disabled} value={props.response.point} onChange={(point) => { props.setStatus("interacting"); props.setResponse({ point }); }}/>;
  }
  if (challenge.type === "scratch") {
    const mask = safeImageDataUri(challenge.presentation.piece);
    return mask ? <ScratchChallenge imageSrc={image} maskSrc={mask} width={challenge.presentation.width} height={challenge.presentation.height} label={localizedPrompt(challenge, locale)} disabled={disabled} startedAt={props.started} onInteractionStart={() => setStatus("interacting")} onSubmit={submit}/> : <SafeImage src={challenge.presentation.piece} alt={localizedPrompt(challenge, locale)}/>;
  }
  if (challenge.type === "curve_draw")
    return (
      <CurveDrawChallenge
        imageSrc={image}
        disabled={disabled}
        alt={localizedPrompt(challenge, locale)}
        onInteractionStart={() => setStatus("interacting")}
        onSubmit={submit}
      />
    );
  if (challenge.type === "curve_slider")
    return (
      <CurveSliderChallenge
        imageSrc={image}
        version={challenge.presentation.version}
        disabled={disabled}
        alt={localizedPrompt(challenge, locale)}
        onInteractionStart={() => setStatus("interacting")}
        onSubmit={submit}
      />
    );
  if (challenge.type === "rotate")
    return (
      <RotatePuzzleChallenge
        challenge={{
          image,
          width: challenge.presentation.width,
          height: challenge.presentation.height,
          pieceSize: challenge.presentation.piece_size,
          initialAngle: challenge.presentation.initial_angle,
          minDurationMs: challenge.presentation.track?.min_duration_ms,
        }}
        disabled={disabled}
        label={localizedPrompt(challenge, locale)}
        onChange={() => setStatus("interacting")}
        onComplete={({ angle, durationMs, track }) =>
          void submit({ angle: Math.round(angle), duration_ms: durationMs, track })
        }
      />
    );
  if (challenge.type === "angle")
    return (
      <AngleChallenge
        challenge={{
          image,
          initialAngle: challenge.presentation.initial_angle ?? 0,
          minDurationMs: challenge.presentation.track?.min_duration_ms,
        }}
        disabled={disabled}
        label={localizedPrompt(challenge, locale)}
        onChange={() => setStatus("interacting")}
        onComplete={({ angle, durationMs, track }) =>
          void submit({ angle: Math.round(angle), duration_ms: durationMs, track })
        }
      />
    );
  if (challenge.type === "restore_slider")
    return (
      <RestoreSliderChallenge
        challenge={{
          image,
          width: challenge.presentation.width,
          height: challenge.presentation.height,
          movingPart: challenge.presentation.moving_part,
          maxOffsetPercent: challenge.presentation.max_offset,
          initialOffsetPercent: challenge.presentation.initial_offset,
        }}
        disabled={disabled}
        label={localizedPrompt(challenge, locale)}
        onChange={() => setStatus("interacting")}
        onComplete={({ offset, track, durationMs }) =>
          void submit({ offset, track, duration_ms: durationMs })
        }
      />
    );
  if (challenge.type === "shape_slider") return <SliderBody {...props} />;
  return <PointerBody {...props} />;
}
function SafeImage({
  src,
  alt,
  className,
  style,
  onLoad,
}: {
  src?: string;
  alt: string;
  className?: string;
  style?: React.CSSProperties;
  onLoad?: React.ReactEventHandler<HTMLImageElement>;
}) {
  const safe = safeImageDataUri(src);
  return safe ? (
    <img
      draggable={false}
      src={safe}
      alt={alt}
      className={className}
      style={style}
      onLoad={onLoad}
    />
  ) : (
    <div className={styles.missingImage} role="alert">
      Invalid or missing image data
    </div>
  );
}

function PointerBody({
  challenge,
  disabled,
  started,
  setResponse,
  setStatus,
  submit,
}: BodyProps) {
  const [track, setTrack] = useState<CaptchaTrackPoint[]>([]);
  const active = useRef<number>();
  const surface = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const scratch = challenge.type === "scratch";
  const resetCanvas = () => {
    const c = canvas.current,
      ctx = c?.getContext("2d");
    if (!c || !ctx) return;
    ctx.clearRect(0, 0, c.width, c.height);
    if (scratch) {
      ctx.fillStyle = "#aeb7c2";
      ctx.fillRect(0, 0, c.width, c.height);
    }
  };
  useEffect(resetCanvas, [challenge.token]);
  const paint = (next: CaptchaTrackPoint[]) => {
    const c = canvas.current,
      ctx = c?.getContext("2d");
    if (!c || !ctx || next.length < 2) return;
    const a = next[next.length - 2],
      b = next[next.length - 1];
    ctx.globalCompositeOperation = scratch ? "destination-out" : "source-over";
    ctx.strokeStyle = "#e23d28";
    ctx.lineWidth = scratch ? 28 : 5;
    ctx.lineCap = "round";
    ctx.beginPath();
    ctx.moveTo((a.x / 10000) * c.width, (a.y / 10000) * c.height);
    ctx.lineTo((b.x / 10000) * c.width, (b.y / 10000) * c.height);
    ctx.stroke();
  };
  const add = (event: React.PointerEvent, kind: string) => {
    if (!surface.current) return track;
    const point = trackPoint(
      normalizePoint(
        event.clientX,
        event.clientY,
        surface.current.getBoundingClientRect(),
      ),
      performance.now() - started.current,
      kind,
    );
    const next = appendTrack(track, point);
    setTrack(next);
    paint(next);
    return next;
  };
  const down = (event: React.PointerEvent) => {
    if (disabled) return;
    active.current = event.pointerId;
    event.currentTarget.setPointerCapture?.(event.pointerId);
    setStatus("interacting");
    setTrack([]);
    resetCanvas();
    add(event, "down");
  };
  const move = (event: React.PointerEvent) => {
    if (active.current === event.pointerId) add(event, "move");
  };
  const up = (event: React.PointerEvent) => {
    if (active.current !== event.pointerId) return;
    const next = add(event, "up");
    active.current = undefined;
    const answer = {
      track: next,
      duration_ms: Math.round(performance.now() - started.current),
    };
    setResponse(answer);
    void submit(answer);
  };
  const cancel = (event: React.PointerEvent) => {
    if (active.current === event.pointerId) {
      active.current = undefined;
      setTrack([]);
      resetCanvas();
      setResponse({});
      setStatus("ready");
    }
  };
  return (
    <div
      ref={surface}
      data-testid="captcha-surface"
      className={styles.surface}
      onPointerDown={down}
      onPointerMove={move}
      onPointerUp={up}
      onPointerCancel={cancel}
    >
      <SafeImage
        src={challenge.presentation.image}
        alt={challenge.presentation.prompt || challenge.type}
      />
      <canvas
        ref={canvas}
        className={styles.overlay}
        width="400"
        height="220"
        aria-hidden="true"
      />
    </div>
  );
}

function SliderBody({
  challenge,
  disabled,
  started,
  setResponse,
  setStatus,
  submit,
}: BodyProps) {
  const [value, setValue] = useState(0);
  const [sliderTrack, setSliderTrack] = useState<CaptchaTrackPoint[]>([]);
  const width = challenge.presentation.width ?? 320;
  const height = challenge.presentation.height ?? 180;
  const pieceSize = challenge.presentation.piece_size ?? 64;
  const pieceY =
    challenge.presentation.piece_y ?? Math.round((height - pieceSize) / 2);
  const pieceStyle = {
    left: `${value / 100}%`,
    top: `${(pieceY / height) * 100}%`,
    width: `${(pieceSize / width) * 100}%`,
    height: `${(pieceSize / height) * 100}%`,
    transform: `translateX(-${value / 100}%)`,
  };
  const pointFor = (v: number) => ({
    x: v,
    y: Math.round(((pieceY + pieceSize / 2) / height) * 10000),
  });
  const change = (v: number) => {
    setStatus("interacting");
    setValue(v);
    setSliderTrack((current) =>
      appendTrack(
        current,
        trackPoint(
          pointFor(v),
          performance.now() - started.current,
          current.length ? "move" : "down",
        ),
      ),
    );
  };
  const finish = () => {
    const point = pointFor(value);
    const duration_ms = Math.round(performance.now() - started.current);
    const track = appendTrack(
      sliderTrack,
      trackPoint(point, duration_ms, "up"),
    );
    const answer = { point, track, duration_ms };
    setResponse(answer);
    setSliderTrack([]);
    void submit(answer);
  };
  return (
    <div className={styles.sliderArea}>
      <div
        className={styles.surface}
        style={{ aspectRatio: `${width} / ${height}` }}
      >
        <SafeImage
          src={challenge.presentation.image}
          alt={challenge.presentation.prompt || challenge.type}
        />
        <SafeImage
          src={challenge.presentation.piece}
          alt="movable puzzle piece"
          className={styles.piece}
          style={pieceStyle}
        />
      </div>
      <input
        className={sliderStyles.range}
        aria-label={challenge.presentation.prompt || challenge.type}
        type="range"
        min="0"
        max="10000"
        value={value}
        style={{ "--captcha-progress": `${value / 100}%` } as React.CSSProperties}
        disabled={disabled}
        onChange={(e) => change(Number(e.target.value))}
        onPointerUp={finish}
        onPointerCancel={() => {
          setSliderTrack([]);
          setResponse({});
          setStatus("ready");
        }}
        onKeyUp={(e) => {
          if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key))
            finish();
        }}
      />
    </div>
  );
}

function PowBody({
  challenge,
  disabled,
  setResponse,
  setStatus,
  submit,
  locale,
}: BodyProps) {
  const controller = useRef<AbortController>();
  const [solving, setSolving] = useState(false);
  useEffect(() => () => controller.current?.abort(), []);
  const run = async () => {
    controller.current?.abort();
    controller.current = new AbortController();
    setSolving(true);
    setStatus("interacting");
    try {
      const proof = await solvePow(
        challenge.presentation.pow_salt || "",
        challenge.presentation.pow_difficulty || 0,
        controller.current.signal,
      );
      const answer = { proof };
      setResponse(answer);
      await submit(answer);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError"))
        setStatus("error");
    } finally {
      setSolving(false);
    }
  };
  return (
    <div className={styles.pow}>
      <button
        type="button"
        className={styles.primary}
        disabled={disabled || solving}
        onClick={() => void run()}
      >
        {solving ? captchaText(locale, "solving") : captchaText(locale, "pow")}
      </button>
      {solving && (
        <button
          type="button"
          className={styles.secondary}
          onClick={() => controller.current?.abort()}
        >
          {captchaText(locale, "cancel")}
        </button>
      )}
    </div>
  );
}

function readyResponse(
  _challenge: CaptchaChallenge,
  response: Omit<CaptchaResponse, "token">,
) {
  return Boolean(response.point);
}
function instruction(type: CaptchaChallenge["type"], locale: CaptchaLocale) {
  if (type === "pow") return captchaText(locale, "pow");
  if (type === "curve_draw") return captchaText(locale, "draw");
  if (type === "scratch") return captchaText(locale, "scratch");
  if (type.endsWith("_click")) return captchaText(locale, "click");
  return captchaText(locale, "drag");
}

function challengeTypeTitle(
  type: CaptchaChallenge["type"],
  locale: CaptchaLocale,
) {
  const zh: Record<CaptchaChallenge["type"], string> = {
    pow: "\u540e\u53f0\u5b89\u5168\u6821\u9a8c",
    curve_draw: "\u66f2\u7ebf\u7ed8\u5236",
    curve_slider: "\u6ed1\u52a8\u66f2\u7ebf",
    shape_slider: "\u6ed1\u5757\u9a8c\u8bc1",
    rotate: "\u65cb\u8f6c\u9a8c\u8bc1",
    restore_slider: "\u6ed1\u52a8\u8fd8\u539f",
    angle: "\u89d2\u5ea6\u9a8c\u8bc1",
    scratch: "\u522e\u522e\u4e50",
    text_click: "\u6587\u5b57\u70b9\u9009",
    icon_click: "\u56fe\u6807\u70b9\u9009",
  };
  const en: Record<CaptchaChallenge["type"], string> = {
    pow: "Security Check",
    curve_draw: "Trace the Curve",
    curve_slider: "Curve Alignment",
    shape_slider: "Shape Puzzle",
    rotate: "Image Rotation",
    restore_slider: "Image Restoration",
    angle: "Angle Match",
    scratch: "Scratch Challenge",
    text_click: "Character Selection",
    icon_click: "Object Selection",
  };
  return locale === "zh-CN" ? zh[type] : en[type];
}
function localizedPrompt(challenge: CaptchaChallenge, locale: CaptchaLocale) {
  const raw = challenge.presentation.prompt?.trim() || "";
  if (locale !== "zh-CN") {
    const scratchTarget = raw.match(/^\u8bf7\u522e\u51fa(?:\u5b8c\u6574\u7684)?[\u201c\"']?(.+?)[\u201d\"']?(?:\u540e\u70b9\u51fb\u6821\u9a8c|\u5e76\u70b9\u51fb\u6821\u9a8c)?$/)?.[1];
    if (scratchTarget) return `Scratch to reveal \u201c${scratchTarget}\u201d, then verify`;
    const textTarget = raw.match(/^请点击字符\s*(.+)$/)?.[1];
    if (textTarget) return `Select character ${textTarget}`;
    const iconTarget = raw.match(/^请点击(最大的|最小的)(蓝色|红色|绿色|黄色|紫色)(.+)$/);
    if (iconTarget) {
      const size = iconTarget[1] === "最大的" ? "largest" : "smallest";
      const colors: Record<string, string> = { 蓝色: "blue", 红色: "red", 绿色: "green", 黄色: "yellow", 紫色: "purple" };
      const shapes: Record<string, string> = { 圆形: "circle", 正方形: "square", 三角形: "triangle", 菱形: "diamond", 正方体: "cube", 圆锥体: "cone", 星形: "star", 爱心: "heart", 包裹: "package", 笑脸: "smiley" };
      return `Select the ${size} ${colors[iconTarget[2]] ?? iconTarget[2]} ${shapes[iconTarget[3]] ?? iconTarget[3]}`;
    }
    return raw || instruction(challenge.type, locale);
  }
  if (raw && /[\u3400-\u9fff]/u.test(raw)) return raw;
  const degree = raw.match(/(\d+)\s*degrees?/i)?.[1];
  const character = raw.match(/character\s+(.+)$/i)?.[1];
  const icon = raw.match(/Click the\s+(.+?)\s+icon/i)?.[1];
  if (degree)
    return (
      "\u8bf7\u5728\u523b\u5ea6\u76d8\u4e0a\u9009\u62e9 " + degree + "\u00b0"
    );
  if (character) return "\u8bf7\u70b9\u9009\u5b57\u7b26 " + character;
  if (icon) return "\u8bf7\u70b9\u9009" + icon + "\u56fe\u6807";
  const prompts: Partial<Record<CaptchaChallenge["type"], string>> = {
    pow: "\u6d4f\u89c8\u5668\u6b63\u5728\u5b8c\u6210\u5b89\u5168\u6821\u9a8c",
    curve_draw:
      "\u8bf7\u4ece\u8d77\u70b9\u6cbf\u53ef\u89c1\u66f2\u7ebf\u7ed8\u5236\u5230\u7bad\u5934",
    curve_slider:
      "\u8bf7\u6cbf\u53ef\u89c1\u8f68\u8ff9\u5c06\u6ed1\u5757\u62d6\u5230\u672b\u7aef",
    shape_slider:
      "\u8bf7\u5c06\u6ed1\u5757\u62d6\u5165\u5339\u914d\u7684\u7f3a\u53e3",
    rotate:
      "\u8bf7\u65cb\u8f6c\u56fe\u50cf\u4f7f\u7bad\u5934\u5782\u76f4\u5411\u4e0a",
    restore_slider:
      "\u8bf7\u6ed1\u52a8\u9519\u4f4d\u533a\u57df\u4f7f\u56fe\u50cf\u5bf9\u9f50",
    scratch: "\u8bf7\u522e\u5f00\u5927\u90e8\u5206\u906e\u7f69\u533a\u57df",
  };
  return prompts[challenge.type] || instruction(challenge.type, locale);
}

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(abortError());
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortError());
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function abortError() {
  return new DOMException("Request aborted", "AbortError");
}

function isAbortError(error: unknown) {
  return error instanceof DOMException && error.name === "AbortError";
}
