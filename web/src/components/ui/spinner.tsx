import { cn } from '@/lib/utils';

function Spinner({ className }: { className?: string }) {
  return (
    <span
      className={cn('inline-block size-5 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent', className)}
      role="status"
      aria-label="Loading"
    />
  );
}

export { Spinner };
