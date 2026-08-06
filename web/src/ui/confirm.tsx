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

  return (
    <AlertDialog
      open
      onOpenChange={(open) => {
        if (!open) {
          props.onCancel?.();
          props.onClose();
        }
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{props.title}</AlertDialogTitle>
          {props.content ? <AlertDialogDescription>{props.content}</AlertDialogDescription> : null}
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogClose
            render={
              <Button
                variant="outline"
                onClick={() => {
                  props.onCancel?.();
                  props.onClose();
                }}
              />
            }
          >
            {props.cancelText || 'Cancel'}
          </AlertDialogClose>
          <Button
            variant={dangerous ? 'destructive' : 'primary'}
            onClick={() => {
              void Promise.resolve(props.onOk?.()).finally(() => props.onClose());
            }}
          >
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
