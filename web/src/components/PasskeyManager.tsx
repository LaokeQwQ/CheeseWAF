import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Fingerprint, Trash2 } from 'lucide-react';
import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  toast,
} from '@/components/ui';
import { APIRequestError, beginPasskeyRegistration, deletePasskeyCredential, fetchPasskeyCredentials, finishPasskeyRegistration } from '../api/client';
import type { PasskeyCredentialSummary } from '../types/api';
import { isPasskeyCancellation, isPasskeySupported, parsePasskeyCreationOptions, passkeyCredentialToJSON } from '../utils/webauthn';

const passkeyCredentialsKey = ['passkey-credentials'];

function passkeyOperationError(error: unknown, t: (key: string) => string) {
  if (isPasskeyCancellation(error)) {
    return t('passkeys.cancelled');
  }
  if (error instanceof APIRequestError && error.code === 'PASSKEY_CREDENTIAL_EXISTS') {
    return t('passkeys.exists');
  }
  if (error instanceof APIRequestError && error.code === 'PASSKEY_DISABLED') {
    return t('passkeys.unavailable');
  }
  return t('passkeys.failed');
}

type PasskeyManagerProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

export default function PasskeyManager({ open, onOpenChange }: PasskeyManagerProps) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const supported = isPasskeySupported();
  const credentials = useQuery({
    queryKey: passkeyCredentialsKey,
    queryFn: fetchPasskeyCredentials,
    enabled: open && supported,
  });
  const add = useMutation({
    mutationFn: async () => {
      const label = name.trim();
      const begin = await beginPasskeyRegistration(label || undefined);
      const credential = await navigator.credentials.create({
        publicKey: parsePasskeyCreationOptions(begin.publicKey),
      }) as PublicKeyCredential | null;
      if (!credential) {
        throw new DOMException('passkey registration was cancelled', 'NotAllowedError');
      }
      return finishPasskeyRegistration(begin.session_token, passkeyCredentialToJSON(credential), label || undefined);
    },
    onSuccess: async () => {
      setName('');
      await queryClient.invalidateQueries({ queryKey: passkeyCredentialsKey });
      toast.success(t('passkeys.added'));
    },
    onError: (error) => toast.error(passkeyOperationError(error, t)),
  });
  const remove = useMutation({
    mutationFn: (id: string) => deletePasskeyCredential(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: passkeyCredentialsKey });
      toast.success(t('passkeys.removed'));
    },
    onError: (error) => toast.error(passkeyOperationError(error, t)),
  });

  const items: PasskeyCredentialSummary[] = credentials.data?.credentials ?? [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>{t('passkeys.title')}</DialogTitle>
          <DialogDescription>{t('passkeys.description')}</DialogDescription>
        </DialogHeader>
        {!supported ? (
          <p className="text-sm text-muted-foreground" role="status">{t('passkeys.unsupported')}</p>
        ) : (
          <div className="grid gap-4">
            <div className="grid gap-1.5">
              <Label htmlFor="passkey-name">{t('passkeys.name')}</Label>
              <div className="flex gap-2">
                <Input
                  id="passkey-name"
                  value={name}
                  maxLength={128}
                  placeholder={t('passkeys.namePlaceholder')}
                  onChange={(event) => setName(event.target.value)}
                />
                <Button type="button" loading={add.isPending} onClick={() => add.mutate()}>
                  <Fingerprint size={16} aria-hidden="true" />
                  <span>{t('passkeys.add')}</span>
                </Button>
              </div>
            </div>
            {credentials.isLoading && <p className="text-sm text-muted-foreground">{t('passkeys.loading')}</p>}
            {credentials.isError && (
              <div className="flex items-center justify-between gap-3 text-sm">
                <span>{t('passkeys.loadFailed')}</span>
                <Button size="sm" variant="outline" onClick={() => void credentials.refetch()}>{t('common.retry')}</Button>
              </div>
            )}
            {!credentials.isLoading && !credentials.isError && items.length === 0 && (
              <p className="text-sm text-muted-foreground">{t('passkeys.empty')}</p>
            )}
            {items.length > 0 && (
              <ul className="grid gap-2">
                {items.map((item) => (
                  <li key={item.id} className="flex items-center justify-between gap-3 rounded-md border px-3 py-2">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{item.name}</p>
                      <p className="truncate text-xs text-muted-foreground">
                        {item.last_used_at
                          ? t('passkeys.lastUsed', { time: new Date(item.last_used_at).toLocaleString() })
                          : t('passkeys.neverUsed')}
                      </p>
                    </div>
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      disabled={remove.isPending}
                      aria-label={t('passkeys.remove')}
                      onClick={() => remove.mutate(item.id)}
                    >
                      <Trash2 size={15} aria-hidden="true" />
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>{t('common.close')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
