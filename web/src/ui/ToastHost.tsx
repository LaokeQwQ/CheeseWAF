import { useEffect, useState } from 'react';
import { dismissToast, subscribeToasts, type ToastItem } from './message';

const kindClass: Record<ToastItem['kind'], string> = {
  success: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-900 dark:text-emerald-100',
  error: 'border-red-500/40 bg-red-500/10 text-red-900 dark:text-red-100',
  warning: 'border-amber-500/40 bg-amber-500/10 text-amber-900 dark:text-amber-100',
  info: 'border-sky-500/40 bg-sky-500/10 text-sky-900 dark:text-sky-100',
};

export default function ToastHost() {
  const [items, setItems] = useState<ToastItem[]>([]);

  useEffect(() => subscribeToasts(setItems), []);

  if (items.length === 0) {
    return null;
  }

  return (
    <div className="pointer-events-none fixed inset-x-0 top-4 z-[10000] flex flex-col items-center gap-2 px-4">
      {items.map((item) => (
        <div
          key={item.id}
          className={`pointer-events-auto max-w-md rounded-lg border px-4 py-2 text-sm shadow-lg backdrop-blur ${kindClass[item.kind]}`}
          role="status"
        >
          <div className="flex items-start gap-3">
            <span className="min-w-0 flex-1 break-words">{item.text}</span>
            <button
              type="button"
              className="shrink-0 opacity-70 hover:opacity-100"
              aria-label="Dismiss"
              onClick={() => dismissToast(item.id)}
            >
              ×
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
