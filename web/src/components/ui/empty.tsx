import * as React from 'react';
import { cn } from '@/lib/utils';

function Empty({ className, description = 'No data', children }: { className?: string; description?: React.ReactNode; children?: React.ReactNode }) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-2 py-12 text-sm text-muted-foreground', className)}>
      <div>{description}</div>
      {children}
    </div>
  );
}

export { Empty };
