import { useCallback, useEffect, useRef, useState, type CSSProperties, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Button } from '@arco-design/web-react';
import { Bot } from 'lucide-react';
import {
  AI_FAB_DEFAULT_BOTTOM,
  AI_FAB_DEFAULT_RIGHT,
  clampFabPosition,
  defaultFabPosition,
  loadFabPosition,
  saveFabPosition,
  type FabPosition,
} from './aiFabPosition';

const DRAG_THRESHOLD_PX = 6;

type AIAssistantFabProps = {
  label: string;
  className?: string;
  loading?: boolean;
  expanded?: boolean;
  controls?: string;
  onActivate: () => void;
  children?: ReactNode;
};

export default function AIAssistantFab({
  label,
  className = '',
  loading = false,
  expanded,
  controls,
  onActivate,
  children,
}: AIAssistantFabProps) {
  const [pos, setPos] = useState<FabPosition | null>(() => loadFabPosition());
  const [dragging, setDragging] = useState(false);
  const dragRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    originLeft: number;
    originTop: number;
    moved: boolean;
  } | null>(null);
  const suppressClickRef = useRef(false);

  const resolvePos = useCallback((current: FabPosition | null) => {
    return clampFabPosition(current ?? defaultFabPosition());
  }, []);

  useEffect(() => {
    function onResize() {
      setPos((current) => (current ? clampFabPosition(current) : current));
    }
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  useEffect(() => {
    if (!dragging) {
      return undefined;
    }
    function onPointerMove(event: PointerEvent) {
      const drag = dragRef.current;
      if (!drag || event.pointerId !== drag.pointerId) {
        return;
      }
      const dx = event.clientX - drag.startX;
      const dy = event.clientY - drag.startY;
      if (!drag.moved && (Math.abs(dx) > DRAG_THRESHOLD_PX || Math.abs(dy) > DRAG_THRESHOLD_PX)) {
        drag.moved = true;
      }
      if (!drag.moved) {
        return;
      }
      event.preventDefault();
      setPos(clampFabPosition({
        left: drag.originLeft + dx,
        top: drag.originTop + dy,
      }));
    }
    function onPointerUp(event: PointerEvent) {
      const drag = dragRef.current;
      if (!drag || event.pointerId !== drag.pointerId) {
        return;
      }
      if (drag.moved) {
        suppressClickRef.current = true;
        setPos((current) => {
          const next = resolvePos(current);
          saveFabPosition(next);
          return next;
        });
      }
      dragRef.current = null;
      setDragging(false);
    }
    window.addEventListener('pointermove', onPointerMove, { passive: false });
    window.addEventListener('pointerup', onPointerUp);
    window.addEventListener('pointercancel', onPointerUp);
    return () => {
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
      window.removeEventListener('pointercancel', onPointerUp);
    };
  }, [dragging, resolvePos]);

  function handlePointerDown(event: ReactPointerEvent<HTMLButtonElement>) {
    if (event.button !== 0) {
      return;
    }
    const current = resolvePos(pos);
    // First interaction materializes the default bottom-right anchor into coordinates.
    if (!pos) {
      setPos(current);
    }
    dragRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      originLeft: current.left,
      originTop: current.top,
      moved: false,
    };
    setDragging(true);
    event.currentTarget.setPointerCapture?.(event.pointerId);
  }

  function handleClick() {
    if (suppressClickRef.current) {
      suppressClickRef.current = false;
      return;
    }
    onActivate();
  }

  const style: CSSProperties = pos
    ? {
        left: pos.left,
        top: pos.top,
        right: 'auto',
        bottom: 'auto',
      }
    : {
        right: AI_FAB_DEFAULT_RIGHT,
        bottom: AI_FAB_DEFAULT_BOTTOM,
        left: 'auto',
        top: 'auto',
      };

  const host = (
    <div className="ai-assistant-host" data-dragging={dragging ? 'true' : 'false'}>
      <Button
        aria-label={label}
        aria-expanded={expanded}
        aria-haspopup={expanded === undefined ? undefined : 'dialog'}
        aria-controls={controls}
        className={['ai-fab', dragging ? 'ai-fab-dragging' : '', className].filter(Boolean).join(' ')}
        type="primary"
        shape="circle"
        loading={loading}
        icon={<Bot size={36} strokeWidth={1.8} />}
        style={style}
        onPointerDown={handlePointerDown}
        onClick={handleClick}
      />
      {children}
    </div>
  );

  if (typeof document === 'undefined') {
    return host;
  }
  return createPortal(host, document.body);
}

