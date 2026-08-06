import { useRef } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { Button } from '@appica/ui-react/button';
import {
  AlertDialog,
  AlertDialogClose,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@appica/ui-react/alert-dialog';

export type ConfirmOptions = {
  title: string;
  content?: string;
  okText?: string;
  cancelText?: string;
  okButtonProps?: { status?: string };
  // Allow any return (e.g. API payloads) — fire-and-forget confirm UX.
  onOk?: () => unknown | Promise<unknown>;
  onCancel?: () => void;
};

function ConfirmDialog(props: ConfirmOptions & { onClose: () => void }) {
  const dangerous = props.okButtonProps?.status === 'danger';
  // Guard against double-fire: cancel button + onOpenChange, or OK then dismiss cleanup.
  const settledRef = useRef(false);

  const dismiss = () => {
    if (settledRef.current) return;
    settledRef.current = true;
    props.onCancel?.();
    props.onClose();
  };

  const accept = () => {
    if (settledRef.current) return;
    settledRef.current = true;
    void Promise.resolve(props.onOk?.()).finally(() => props.onClose());
  };

  return (
    <AlertDialog
      open
      onOpenChange={(open) => {
        if (!open) dismiss();
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{props.title}</AlertDialogTitle>
          {props.content ? <AlertDialogDescription>{props.content}</AlertDialogDescription> : null}
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogClose render={<Button variant="outline" />}>
            {props.cancelText || 'Cancel'}
          </AlertDialogClose>
          <Button variant={dangerous ? 'destructive' : 'primary'} onClick={accept}>
            {props.okText || 'OK'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

let host: HTMLDivElement | null = null;
let root: Root | null = null;

export function confirm(options: ConfirmOptions) {
  if (!host) {
    host = document.createElement('div');
    document.body.appendChild(host);
    root = createRoot(host);
  }

  const close = () => {
    root?.render(null);
  };

  root?.render(<ConfirmDialog {...options} onClose={close} />);
}

export const Modal = {
  confirm,
};
