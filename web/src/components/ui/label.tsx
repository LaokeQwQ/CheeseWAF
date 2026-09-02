import * as React from 'react';
import * as LabelPrimitive from '@radix-ui/react-label';
import { cn } from '@/lib/utils';

const Label = React.forwardRef<
  React.ElementRef<typeof LabelPrimitive.Root>,
  React.ComponentPropsWithoutRef<typeof LabelPrimitive.Root>
>(({ className, htmlFor, ...props }, forwardedRef) => {
  const labelRef = React.useRef<HTMLLabelElement>(null);
  const generatedID = React.useId();

  React.useImperativeHandle(forwardedRef, () => labelRef.current!, []);

  React.useLayoutEffect(() => {
    const label = labelRef.current;
    if (!label || htmlFor) {
      return;
    }
    const control = label.parentElement?.querySelector<HTMLElement>(
      'input:not([type="hidden"]), textarea, select, button[role="switch"], button[role="combobox"], button[role="checkbox"]',
    );
    if (!control) {
      return;
    }
    if (!control.id) {
      control.id = `field-${generatedID}`;
    }
    label.htmlFor = control.id;
  }, [generatedID, htmlFor]);

  return (
    <LabelPrimitive.Root
      ref={labelRef}
      htmlFor={htmlFor}
      className={cn('text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70', className)}
      {...props}
    />
  );
});
Label.displayName = LabelPrimitive.Root.displayName;

export { Label };
