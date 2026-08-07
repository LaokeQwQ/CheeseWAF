type MessageKind = 'success' | 'error' | 'warning' | 'info';

export type ToastItem = {
  id: string;
  kind: MessageKind;
  text: string;
};

type Listener = (items: ToastItem[]) => void;

const listeners = new Set<Listener>();
let items: ToastItem[] = [];

function emit() {
  const snapshot = items.slice();
  listeners.forEach((listener) => listener(snapshot));
}

function push(kind: MessageKind, text: string) {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  items = [...items, { id, kind, text: String(text) }];
  emit();
  window.setTimeout(() => {
    items = items.filter((item) => item.id !== id);
    emit();
  }, 4200);
}

export const Message = {
  success: (text: string) => push('success', text),
  error: (text: string) => push('error', text),
  warning: (text: string) => push('warning', text),
  info: (text: string) => push('info', text),
};

export function subscribeToasts(listener: Listener) {
  listeners.add(listener);
  listener(items.slice());
  return () => {
    listeners.delete(listener);
  };
}

export function dismissToast(id: string) {
  items = items.filter((item) => item.id !== id);
  emit();
}
