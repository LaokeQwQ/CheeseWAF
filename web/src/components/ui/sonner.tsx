import * as React from 'react';
import { Toaster as Sonner } from 'sonner';
import { useAppStore } from '../../stores';

type ToasterProps = React.ComponentProps<typeof Sonner>;

function Toaster({ ...props }: ToasterProps) {
  const appTheme = useAppStore((state) => state.theme);
  // Sonner only supports light/dark/system; map app themes to a real scheme.
  const theme = appTheme === 'dark' || appTheme === 'blackGold' ? 'dark' : 'light';
  return (
    <Sonner
      className="toaster group"
      toastOptions={{
        classNames: {
          toast: 'group toast group-[.toaster]:bg-background group-[.toaster]:text-foreground group-[.toaster]:border-border group-[.toaster]:shadow-lg',
          description: 'group-[.toast]:text-muted-foreground',
          actionButton: 'group-[.toast]:bg-primary group-[.toast]:text-primary-foreground',
          cancelButton: 'group-[.toast]:bg-muted group-[.toast]:text-muted-foreground',
        },
      }}
      {...props}
      theme={theme}
    />
  );
}

export { Toaster };
