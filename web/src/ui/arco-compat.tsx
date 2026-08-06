/**
 * Arco-shaped helpers on top of Appica so page migrations can proceed
 * without rewriting every Form.useForm / Table columns call in one pass.
 */
import {
  Children,
  createContext,
  isValidElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type FormEvent,
  type ReactElement,
  type ReactNode,
} from 'react';
import {
  Button as AppicaButton,
  type ButtonProps as AppicaButtonProps,
} from '@appica/ui-react/button';
import { Input as AppicaInput } from '@appica/ui-react/input';
import { Checkbox as AppicaCheckbox } from '@appica/ui-react/checkbox';
import {
  Select as AppicaSelect,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@appica/ui-react/select';
import {
  Table as AppicaTable,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@appica/ui-react/table';
import {
  Tabs as AppicaTabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@appica/ui-react/tabs';
import {
  Tooltip as AppicaTooltip,
  TooltipContent,
  TooltipTrigger,
} from '@appica/ui-react/tooltip';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@appica/ui-react/dropdown-menu';
import {
  Popover as AppicaPopover,
  PopoverContent,
  PopoverTrigger,
} from '@appica/ui-react/popover';
import { Badge } from '@appica/ui-react/badge';
import { Spinner } from '@appica/ui-react/spinner';
import { Progress as AppicaProgress } from '@appica/ui-react/progress';
import { Skeleton as AppicaSkeleton } from '@appica/ui-react/skeleton';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@appica/ui-react/dialog';
import { confirm, type ConfirmOptions } from './confirm';
import { Message } from './message';

// `any` bag matches Arco Form values so `values.foo ?? default` stays typed for pages.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type FormValues = Record<string, any>;

type FieldRule = {
  required?: boolean;
  message?: string;
  /** Arco-compatible pattern rule (e.g. Operations `timeRules` HH:mm). */
  match?: RegExp;
  validator?: (value: unknown, callback: (error?: string) => void) => void;
};

type FormApi = {
  getFieldsValue: () => FormValues;
  setFieldsValue: (patch: FormValues) => void;
  resetFields: () => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  validate: () => Promise<any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getFieldValue: (field: string) => any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  setFieldValue: (field: string, value: any) => void;
};

type FormContextValue = {
  values: FormValues;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  setValue: (field: string, value: any) => void;
  form: FormApi;
};

const FormContext = createContext<FormContextValue | null>(null);

type FormStore = FormApi & {
  subscribe: (listener: () => void) => () => void;
  getSnapshot: () => FormValues;
  registerRules: (field: string, rules: FieldRule[] | undefined) => () => void;
  /** Remember defaults so resetFields() restores Form initialValues (not empty {}). */
  replaceInitialValues: (next: FormValues) => void;
};

function isEmptyFormValue(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (typeof value === 'string' && value.trim() === '') return true;
  if (Array.isArray(value) && value.length === 0) return true;
  return false;
}

function createFormStore(initial: FormValues = {}): FormStore {
  let values: FormValues = { ...initial };
  let baseline: FormValues = { ...initial };
  const listeners = new Set<() => void>();
  const fieldRules = new Map<string, FieldRule[]>();
  const notify = () => listeners.forEach((listener) => listener());
  return {
    getFieldsValue: () => ({ ...values }),
    setFieldsValue: (patch) => {
      values = { ...values, ...patch };
      notify();
    },
    resetFields: () => {
      values = { ...baseline };
      notify();
    },
    replaceInitialValues: (next) => {
      baseline = { ...next };
    },
    validate: async () => {
      const errors: Record<string, string> = {};
      for (const [field, rules] of fieldRules) {
        const value = values[field];
        for (const rule of rules) {
          if (rule.required && isEmptyFormValue(value)) {
            errors[field] = rule.message || 'Required';
            break;
          }
          if (rule.match instanceof RegExp && !isEmptyFormValue(value) && !rule.match.test(String(value))) {
            errors[field] = rule.message || 'Invalid';
            break;
          }
          if (rule.validator) {
            const message = await new Promise<string | undefined>((resolve) => {
              let settled = false;
              const done = (error?: string) => {
                if (settled) return;
                settled = true;
                resolve(error);
              };
              try {
                rule.validator?.(value, done);
              } catch (error) {
                done(error instanceof Error ? error.message : String(error));
              }
            });
            if (message) {
              errors[field] = message;
              break;
            }
          }
        }
      }
      if (Object.keys(errors).length > 0) {
        return Promise.reject(errors);
      }
      return { ...values };
    },
    getFieldValue: (field) => values[field],
    setFieldValue: (field, value) => {
      values = { ...values, [field]: value };
      notify();
    },
    registerRules: (field, rules) => {
      if (rules && rules.length > 0) {
        fieldRules.set(field, rules);
      } else {
        fieldRules.delete(field);
      }
      return () => {
        fieldRules.delete(field);
      };
    },
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    getSnapshot: () => values,
  };
}

export function useForm<T extends FormValues = FormValues>(): [FormStore & { __values?: T }] {
  const store = useMemo(() => createFormStore(), []);
  return [store as FormStore & { __values?: T }];
}

export function Form(props: {
  form?: FormStore | FormApi;
  initialValues?: FormValues;
  layout?: string;
  className?: string;
  style?: CSSProperties;
  children?: ReactNode;
  // method form so typed draft handlers assign without casts
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onSubmit?(values: any): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onValuesChange?(changed: any, all: any): void;
  // allow pages that pass typed handlers
  [key: string]: unknown;
}) {
  const [fallback] = useForm();
  const store = (props.form as FormStore) || fallback;
  const [, bump] = useState(0);
  const seededRef = useRef(false);

  // Seed before first paint / before subscribe, so Form.Item sees values immediately.
  // (useEffect seed + later subscribe previously lost the first notify.)
  // Also pin resetFields baseline to initialValues (useForm() store starts as {}).
  if (!seededRef.current && props.initialValues) {
    store.setFieldsValue(props.initialValues);
    if ('replaceInitialValues' in store) {
      (store as FormStore).replaceInitialValues(props.initialValues);
    }
    seededRef.current = true;
  }

  useEffect(() => {
    if (!('subscribe' in store)) return undefined;
    return store.subscribe(() => bump((n) => n + 1));
  }, [store]);

  const values = store.getFieldsValue();

  // Keep latest handlers in refs so setValue identity stays stable (avoids re-render churn).
  const onValuesChangeRef = useRef(props.onValuesChange);
  onValuesChangeRef.current = props.onValuesChange;
  const onSubmitRef = useRef(props.onSubmit);
  onSubmitRef.current = props.onSubmit;

  const setValue = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (field: string, value: any) => {
      store.setFieldsValue({ [field]: value });
      const all = store.getFieldsValue();
      onValuesChangeRef.current?.({ [field]: value }, all);
    },
    [store],
  );

  return (
    <FormContext.Provider value={{ values, setValue, form: store }}>
      <form
        className={props.className}
        style={props.style}
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          // Arco Form validates registered field rules before onSubmit.
          void store
            .validate()
            .then((next) => {
              onSubmitRef.current?.(next);
            })
            .catch(() => {
              /* validation failed — form.validate() callers handle rejection themselves */
            });
        }}
      >
        {props.children as ReactNode}
      </form>
    </FormContext.Provider>
  );
}

Form.useForm = useForm;

type ListField = { key: number; field: string };
Form.List = function FormList(props: {
  field: string;
  children?: (
    fields: ListField[],
    ops: { add: (defaultValue?: unknown) => void; remove: (index: number | string) => void },
  ) => ReactNode;
}) {
  const ctx = useContext(FormContext);
  const raw = props.field ? ctx?.values[props.field] : undefined;
  const list = Array.isArray(raw) ? raw : [];
  // Stable keys (Arco-style): survive reorders/removes better than bare indices.
  const keySeq = useRef(0);
  const keysRef = useRef<number[]>([]);
  if (keysRef.current.length < list.length) {
    while (keysRef.current.length < list.length) {
      keysRef.current.push(keySeq.current++);
    }
  } else if (keysRef.current.length > list.length) {
    keysRef.current = keysRef.current.slice(0, list.length);
  }
  const fields: ListField[] = list.map((_, index) => ({
    key: keysRef.current[index],
    field: `${props.field}[${index}]`,
  }));
  const add = (defaultValue: unknown = '') => {
    if (!props.field || !ctx) return;
    keysRef.current = [...keysRef.current, keySeq.current++];
    ctx.setValue(props.field, [...list, defaultValue]);
  };
  const remove = (indexOrKey: number | string) => {
    if (!props.field || !ctx) return;
    const n = typeof indexOrKey === 'number' ? indexOrKey : Number(indexOrKey);
    if (!Number.isFinite(n)) return;
    // Prefer matching field.key; fall back to array index (Arco remove(index)).
    let idx = keysRef.current.indexOf(n);
    if (idx < 0) idx = n;
    if (idx < 0 || idx >= list.length) return;
    keysRef.current = keysRef.current.filter((_, i) => i !== idx);
    ctx.setValue(
      props.field,
      list.filter((_, i) => i !== idx),
    );
  };
  return <>{props.children?.(fields, { add, remove })}</>;
};

Form.Item = function FormItem(props: {
  field?: string;
  label?: ReactNode;
  rules?: FieldRule[];
  children?: ReactNode;
  className?: string;
  extra?: ReactNode;
  triggerPropName?: string;
  normalize?: (value: unknown) => unknown;
  disabled?: boolean;
  style?: CSSProperties;
  noStyle?: boolean;
  [key: string]: unknown;
}) {
  const ctx = useContext(FormContext);
  const formApi = ctx?.form;
  // Register rules so form.validate() / submit can enforce required + custom validators.
  // Depend on formApi (stable store), not whole ctx, to avoid re-register on every value change.
  useEffect(() => {
    if (!props.field || !formApi || !('registerRules' in formApi)) return undefined;
    return (formApi as FormStore).registerRules(props.field, props.rules);
  }, [formApi, props.field, props.rules]);

  const child = Children.count(props.children) === 1 ? (Children.only(props.children) as ReactElement) : null;
  let value = props.field ? ctx?.values[props.field] : undefined;
  // support Form.List nested fields like "items[0]"
  if (props.field && ctx && props.field.includes('[')) {
    const match = /^([^\[]+)\[(\d+)\](?:\.(.+))?$/.exec(props.field);
    if (match) {
      const list = ctx.values[match[1]];
      if (Array.isArray(list)) {
        const item = list[Number(match[2])];
        value = match[3] && item && typeof item === 'object' ? (item as FormValues)[match[3]] : item;
      }
    }
  }
  // Arco Form.Item accepts either `required` boolean or rules[].required for the asterisk.
  // (Do not auto-register a required rule from the boolean alone — pages like RulesPage
  // rely on submit reaching their own draft validators / Message.warning path.)
  const required =
    Boolean((props as { required?: boolean }).required) || Boolean(props.rules?.some((rule) => rule.required));
  const trigger = props.triggerPropName || 'value';

  // String labels become aria-label (fallback for getByRole name / getByLabelText).
  // When field is set, also wire label htmlFor ↔ control id for proper a11y association.
  const ariaLabel =
    typeof props.label === 'string' || typeof props.label === 'number' ? String(props.label) : undefined;
  const childId =
    child && isValidElement(child) ? (child.props as { id?: string }).id : undefined;
  const controlId = props.field
    ? childId || `form-field-${String(props.field).replace(/[^\w.-]+/g, '-')}`
    : childId;

  // Keep arrays/objects (multi-select) intact; only default undefined/null to ''.
  const boundValue =
    trigger === 'checked'
      ? Boolean(value)
      : value === undefined || value === null
        ? ''
        : value;

  const control = child && isValidElement(child)
    ? {
        ...child,
        props: {
          ...(child.props as Record<string, unknown>),
          [trigger]:
            (child.props as { value?: unknown; checked?: unknown })[trigger as 'value'] ?? boundValue,
          checked:
            trigger === 'checked'
              ? Boolean(value)
              : (child.props as { checked?: boolean }).checked,
          ...(controlId ? { id: controlId } : {}),
          // Keep aria-label so tests using name: 'login.username' still resolve.
          'aria-label':
            (child.props as { 'aria-label'?: string })['aria-label'] || ariaLabel,
          onChange: (next: unknown) => {
            let resolved: unknown = next;
            // Unwrap DOM events only — not arrays (multi-select) or plain value objects.
            if (
              next != null &&
              typeof next === 'object' &&
              !Array.isArray(next) &&
              'target' in (next as { target?: unknown })
            ) {
              const target = (next as { target: { type?: string; value?: unknown; checked?: unknown } }).target;
              resolved = target.type === 'checkbox' || trigger === 'checked' ? target.checked : target.value;
            }
            if (props.normalize) {
              resolved = props.normalize(resolved);
            }
            if (props.field) {
              if (props.field.includes('[') && ctx) {
                const match = /^([^\[]+)\[(\d+)\](?:\.(.+))?$/.exec(props.field);
                if (match) {
                  const listName = match[1];
                  const idx = Number(match[2]);
                  const list = Array.isArray(ctx.values[listName]) ? [...(ctx.values[listName] as unknown[])] : [];
                  if (match[3] && list[idx] && typeof list[idx] === 'object') {
                    list[idx] = { ...(list[idx] as object), [match[3]]: resolved };
                  } else {
                    list[idx] = resolved;
                  }
                  ctx.setValue(listName, list);
                } else {
                  ctx.setValue(props.field, resolved);
                }
              } else {
                ctx?.setValue(props.field, resolved);
              }
            }
            const original = (child.props as { onChange?: (v: unknown) => void }).onChange;
            original?.(resolved);
          },
        },
      }
    : props.children;

  if (props.noStyle) {
    return <>{control}</>;
  }

  return (
    <div className={`arco-form-item mb-3 flex flex-col gap-1.5 ${props.className || ''}`.trim()} style={props.style}>
      {props.label ? (
        <label
          className="arco-form-item-label arco-form-label-item text-sm font-medium text-foreground-intense"
          htmlFor={controlId || undefined}
        >
          {required ? <span className="text-red-500">* </span> : null}
          {props.label}
        </label>
      ) : null}
      {control}
      {props.extra ? <div className="arco-form-extra text-xs text-foreground-muted">{props.extra}</div> : null}
    </div>
  );
};

function mapButtonSize(size?: string | null): AppicaButtonProps['size'] {
  switch (size) {
    case 'mini':
    case 'small':
    case 'sm':
      return 'sm';
    case 'large':
    case 'lg':
      return 'lg';
    case 'default':
    case 'middle':
    case 'md':
      return 'md';
    default:
      return size as AppicaButtonProps['size'];
  }
}

function mapButtonVariant(
  type?: string,
  status?: string,
  variant?: string,
): AppicaButtonProps['variant'] {
  if (status === 'danger' || status === 'error') return 'destructive';
  if (variant) return variant as AppicaButtonProps['variant'];
  switch (type) {
    case 'primary':
      return 'primary';
    case 'secondary':
      return 'secondary';
    case 'outline':
    case 'dashed':
      return 'outline';
    case 'text':
    case 'link':
      return 'ghost';
    case 'default':
    case undefined:
      return 'outline';
    default:
      // if type is html button type, ignore
      if (type === 'button' || type === 'submit' || type === 'reset') return 'outline';
      return 'outline';
  }
}

export function Button(
  props: {
    type?: string;
    htmlType?: 'button' | 'submit' | 'reset';
    size?: string;
    status?: string;
    variant?: string;
    loading?: boolean;
    icon?: ReactNode;
    disabled?: boolean;
    className?: string;
    style?: CSSProperties;
    children?: ReactNode;
    onClick?: (event?: unknown) => void;
    long?: boolean;
    shape?: string;
    href?: string;
    target?: string;
    'aria-label'?: string;
    'aria-expanded'?: boolean;
    'aria-haspopup'?: string | boolean;
    'aria-controls'?: string;
    [key: string]: unknown;
  },
) {
  const htmlType =
    props.htmlType ||
    (props.type === 'submit' || props.type === 'reset' || props.type === 'button'
      ? (props.type as 'button' | 'submit' | 'reset')
      : 'button');
  const variant = mapButtonVariant(props.type, props.status, props.variant);
  const size = mapButtonSize(props.size);
  const disabled = Boolean(props.disabled || props.loading);

  const classes = [
    'arco-btn',
    variant === 'primary' ? 'arco-btn-primary' : '',
    disabled ? 'arco-btn-disabled' : '',
    props.className || '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <AppicaButton
      type={htmlType}
      variant={variant}
      size={size}
      disabled={disabled}
      className={classes}
      style={props.style}
      data-variant={variant || undefined}
      data-size={size || undefined}
      onClick={props.onClick as AppicaButtonProps['onClick']}
      aria-label={props['aria-label']}
      aria-expanded={props['aria-expanded']}
      aria-haspopup={props['aria-haspopup'] as AppicaButtonProps['aria-haspopup']}
      aria-controls={props['aria-controls']}
    >
      {props.loading ? <Spinner className="mr-1 size-3.5" /> : null}
      {props.icon ? <span className="inline-flex items-center">{props.icon}</span> : null}
      {props.children}
    </AppicaButton>
  );
}

// Method syntax keeps callbacks bivariant so (v: string) => void / setState assign cleanly.
type InputChangeHandler = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (value: any, event?: any): void;
};

function callInputChange(handler: InputChangeHandler | undefined, value: string, event: unknown) {
  if (!handler) return;
  handler(value, event);
}

export function Input(props: {
  value?: string | number;
  defaultValue?: string | number;
  onChange?: InputChangeHandler;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onPressEnter?(event: any): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onKeyDown?(event: any): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onFocus?(event: any): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onBlur?(event: any): void;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  style?: CSSProperties;
  allowClear?: boolean;
  type?: string;
  maxLength?: number;
  readOnly?: boolean;
  autoComplete?: string;
  prefix?: ReactNode;
  suffix?: ReactNode;
  addBefore?: ReactNode;
  addAfter?: ReactNode;
  size?: string;
  status?: string;
  id?: string;
  'aria-label'?: string;
  'aria-expanded'?: boolean | 'true' | 'false';
  'aria-controls'?: string;
  [key: string]: unknown;
}) {
  return (
    <AppicaInput
      id={props.id}
      type={props.type || 'text'}
      value={props.value === undefined || props.value === null ? undefined : String(props.value)}
      defaultValue={props.defaultValue === undefined || props.defaultValue === null ? undefined : String(props.defaultValue)}
      placeholder={props.placeholder}
      disabled={props.disabled}
      readOnly={props.readOnly}
      className={`arco-input ${props.className || ''}`.trim()}
      style={props.style}
      maxLength={props.maxLength}
      autoComplete={props.autoComplete}
      clearable={props.allowClear}
      // Controlled clear: Appica only mutates DOM when uncontrolled; always notify onChange.
      onClear={
        props.allowClear
          ? () => {
              callInputChange(props.onChange, '', undefined);
            }
          : undefined
      }
      startSlot={props.prefix || props.addBefore}
      endSlot={props.suffix || props.addAfter}
      aria-label={props['aria-label']}
      aria-expanded={props['aria-expanded']}
      aria-controls={props['aria-controls']}
      onChange={(event) => {
        const value = event.target.value;
        callInputChange(props.onChange, value, event);
      }}
      onFocus={props.onFocus}
      onBlur={props.onBlur}
      onKeyDown={(event) => {
        props.onKeyDown?.(event);
        if (event.key === 'Enter') {
          props.onPressEnter?.(event);
        }
      }}
    />
  );
}

Input.Password = function InputPassword(props: {
  value?: string;
  defaultValue?: string;
  onChange?: InputChangeHandler;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  style?: CSSProperties;
  [key: string]: unknown;
}) {
  return (
    <Input
      {...props}
      type="password"
      value={props.value}
      defaultValue={props.defaultValue}
      onChange={props.onChange}
      placeholder={props.placeholder}
      disabled={props.disabled}
      className={props.className}
      style={props.style}
    />
  );
};

Input.TextArea = function InputTextArea(props: {
  value?: string;
  defaultValue?: string;
  onChange?: InputChangeHandler;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  style?: CSSProperties;
  rows?: number;
  autoSize?: boolean | { minRows?: number; maxRows?: number };
  maxLength?: number;
  id?: string;
  [key: string]: unknown;
}) {
  const minRows =
    typeof props.autoSize === 'object' && props.autoSize?.minRows
      ? props.autoSize.minRows
      : props.rows || 3;
  return (
    <textarea
      id={props.id}
      className={`arco-textarea w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring ${props.className || ''}`.trim()}
      style={props.style}
      value={props.value ?? ''}
      defaultValue={props.defaultValue}
      placeholder={props.placeholder}
      disabled={props.disabled}
      rows={minRows}
      maxLength={props.maxLength}
      aria-label={(props as { 'aria-label'?: string })['aria-label']}
      onChange={(event) => callInputChange(props.onChange, event.target.value, event)}
    />
  );
};

Input.Search = function InputSearch(props: {
  value?: string;
  onChange?: InputChangeHandler;
  onSearch?: (value: string) => void;
  placeholder?: string;
  className?: string;
  style?: CSSProperties;
  [key: string]: unknown;
}) {
  return (
    <Input
      {...props}
      value={props.value}
      onChange={props.onChange}
      placeholder={props.placeholder}
      className={props.className}
      style={props.style}
      onPressEnter={() => props.onSearch?.(String(props.value || ''))}
      suffix={
        <button type="button" className="text-xs text-foreground-muted" onClick={() => props.onSearch?.(String(props.value || ''))}>
          Search
        </button>
      }
    />
  );
};

type SelectOptionItem = { label: ReactNode; value: string | number; disabled?: boolean };

/** Flatten Select.Option / Select.OptGroup children (and props.options) into a flat option list. */
function collectSelectOptions(
  options: SelectOptionItem[] | undefined,
  children: ReactNode,
): SelectOptionItem[] {
  if (options) return options;
  const out: SelectOptionItem[] = [];
  const walk = (nodes: ReactNode) => {
    Children.forEach(nodes, (child) => {
      if (!isValidElement(child)) return;
      const el = child as ReactElement<{
        value?: string | number;
        children?: ReactNode;
        disabled?: boolean;
      }>;
      if (el.props.value !== undefined && el.props.value !== null) {
        out.push({
          label: el.props.children,
          value: el.props.value,
          disabled: el.props.disabled,
        });
        return;
      }
      if (el.props.children != null) {
        walk(el.props.children);
      }
    });
  };
  walk(children);
  return out;
}

function normalizeMultiSelectValue(
  value: string | number | Array<string | number> | undefined | null,
): Array<string | number> {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value;
  if (typeof value === 'string' && value === '') return [];
  return [value];
}

export function Select(props: {
  value?: string | number | Array<string | number> | undefined;
  defaultValue?: string | number | Array<string | number>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onChange?: (value: any) => void;
  options?: Array<{ label: ReactNode; value: string | number; disabled?: boolean }>;
  placeholder?: string;
  allowClear?: boolean;
  disabled?: boolean;
  className?: string;
  style?: CSSProperties;
  children?: ReactNode;
  mode?: string;
  showSearch?: boolean;
  prefix?: ReactNode;
  size?: string;
  triggerProps?: unknown;
  getPopupContainer?: unknown;
  filterOption?: unknown;
  'aria-label'?: string;
  [key: string]: unknown;
}) {
  const options = collectSelectOptions(props.options, props.children);
  const ariaLabel = props['aria-label'];
  const isMultiple = props.mode === 'multiple' || props.mode === 'tags';

  if (isMultiple) {
    const selected = normalizeMultiSelectValue(props.value);
    const selectedKeys = new Set(selected.map(String));
    const selectedOptions = options.filter((option) => selectedKeys.has(String(option.value)));
    const toggle = (optionValue: string | number) => {
      if (props.disabled) return;
      const key = String(optionValue);
      const nextKeys = new Set(selectedKeys);
      if (nextKeys.has(key)) nextKeys.delete(key);
      else nextKeys.add(key);
      // Preserve original option value types where possible.
      const next = options
        .filter((option) => nextKeys.has(String(option.value)))
        .map((option) => option.value);
      // Keep free-form values (allowCreate / tags) that are not in options.
      for (const item of selected) {
        if (!options.some((option) => String(option.value) === String(item)) && nextKeys.has(String(item))) {
          next.push(item);
        }
      }
      props.onChange?.(next);
    };

    return (
      <div
        className={`arco-select arco-select-multiple flex min-w-[10rem] flex-col gap-1.5 ${props.disabled ? 'arco-select-disabled' : ''} ${props.className || ''}`.trim()}
        style={props.style}
        role="group"
        aria-label={ariaLabel}
        aria-disabled={props.disabled || undefined}
        data-mode="multiple"
      >
        {props.prefix ? <span className="text-foreground-muted" aria-hidden="true">{props.prefix}</span> : null}
        <div className="flex flex-wrap items-center gap-1.5">
          {selectedOptions.length === 0 && selected.length === 0 ? (
            <span className="text-sm text-foreground-muted">{props.placeholder || 'Select'}</span>
          ) : (
            <>
              {selectedOptions.map((option) => (
                <Badge key={String(option.value)} className="gap-1">
                  {option.label}
                  {!props.disabled ? (
                    <button
                      type="button"
                      className="ml-0.5 text-xs opacity-70 hover:opacity-100"
                      aria-label={`Remove ${String(option.value)}`}
                      onClick={() => toggle(option.value)}
                    >
                      ×
                    </button>
                  ) : null}
                </Badge>
              ))}
              {selected
                .filter((item) => !options.some((option) => String(option.value) === String(item)))
                .map((item) => (
                  <Badge key={String(item)} className="gap-1">
                    {String(item)}
                    {!props.disabled ? (
                      <button
                        type="button"
                        className="ml-0.5 text-xs opacity-70 hover:opacity-100"
                        aria-label={`Remove ${String(item)}`}
                        onClick={() => toggle(item)}
                      >
                        ×
                      </button>
                    ) : null}
                  </Badge>
                ))}
            </>
          )}
          {props.allowClear && selected.length > 0 && !props.disabled ? (
            <button
              type="button"
              className="text-xs text-foreground-muted underline-offset-2 hover:underline"
              onClick={() => props.onChange?.([])}
            >
              Clear
            </button>
          ) : null}
        </div>
        <div className="flex max-h-48 flex-col gap-1 overflow-auto rounded-lg border border-border p-2">
          {options.map((option) => {
            const key = String(option.value);
            const checked = selectedKeys.has(key);
            return (
              <label
                key={key}
                className={`inline-flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-sm ${
                  option.disabled || props.disabled ? 'cursor-not-allowed opacity-50' : 'hover:bg-muted/40'
                }`}
              >
                <AppicaCheckbox
                  checked={checked}
                  disabled={option.disabled || props.disabled}
                  onCheckedChange={() => toggle(option.value)}
                />
                <span>{option.label}</span>
              </label>
            );
          })}
        </div>
      </div>
    );
  }

  const stringValue =
    props.value === undefined || props.value === null
      ? undefined
      : String(Array.isArray(props.value) ? props.value[0] : props.value);

  const selected = options.find((option) => String(option.value) === stringValue);
  // Keep selected labels in the document (closed Appica select may not mirror option text).
  const selectedLabel = selected?.label;

  return (
    <div
      className={`arco-select inline-flex items-center gap-1 ${props.disabled ? 'arco-select-disabled' : ''} ${props.className || ''}`.trim()}
      style={props.style}
    >
      {props.prefix ? <span className="text-foreground-muted" aria-hidden="true">{props.prefix}</span> : null}
      <AppicaSelect
        value={stringValue}
        defaultValue={
          props.defaultValue === undefined || Array.isArray(props.defaultValue)
            ? undefined
            : String(props.defaultValue)
        }
        onValueChange={(next) => props.onChange?.(next)}
        disabled={props.disabled}
      >
        <SelectTrigger
          clearable={props.allowClear}
          aria-label={ariaLabel}
          className={`arco-select-view ${props.disabled ? 'arco-select-view-disabled' : ''}`.trim()}
        >
          <SelectValue placeholder={props.placeholder || 'Select'}>{selectedLabel}</SelectValue>
        </SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={String(option.value)} value={String(option.value)} disabled={option.disabled}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </AppicaSelect>
    </div>
  );
}

Select.Option = function SelectOption(_props: { value: string | number; children?: ReactNode; disabled?: boolean }) {
  return null;
};

Select.OptGroup = function SelectOptGroup(props: { label?: ReactNode; children?: ReactNode }) {
  return <>{props.children}</>;
};

export function InputNumber(props: {
  value?: number | string | null;
  defaultValue?: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onChange?: (value: any) => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onFocus?(event: any): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onBlur?(event: any): void;
  min?: number;
  max?: number;
  step?: number;
  disabled?: boolean;
  className?: string;
  placeholder?: string;
  style?: CSSProperties;
  precision?: number;
  mode?: string;
  suffix?: ReactNode;
  prefix?: ReactNode;
  [key: string]: unknown;
}) {
  const display =
    props.value === undefined || props.value === null || (typeof props.value === 'number' && Number.isNaN(props.value))
      ? ''
      : String(props.value);
  return (
    <Input
      type="number"
      className={props.className}
      style={props.style}
      disabled={props.disabled}
      placeholder={props.placeholder}
      value={display}
      min={props.min}
      max={props.max}
      step={props.step}
      prefix={props.prefix}
      suffix={props.suffix}
      onFocus={props.onFocus}
      onBlur={props.onBlur}
      onChange={(raw) => {
        const text = String(raw ?? '');
        if (text === '') {
          props.onChange?.(undefined);
          return;
        }
        const num = Number(text);
        if (!Number.isFinite(num)) {
          props.onChange?.(undefined);
          return;
        }
        if (typeof props.precision === 'number') {
          props.onChange?.(Number(num.toFixed(props.precision)));
          return;
        }
        props.onChange?.(num);
      }}
    />
  );
}

export function Switch(props: {
  checked?: boolean;
  defaultChecked?: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onChange?: (checked: any) => void;
  disabled?: boolean;
  loading?: boolean;
  size?: string;
  type?: string;
  checkedText?: ReactNode;
  uncheckedText?: ReactNode;
  className?: string;
  id?: string;
  'aria-label'?: string;
  [key: string]: unknown;
}) {
  // Lightweight native switch: keeps Arco class hooks (`.arco-switch` /
  // `.arco-switch-checked`) reliable for tests and page CSS, and avoids
  // Appica/Base UI motion + hidden-input label double-toggle issues in jsdom.
  const controlled = props.checked !== undefined;
  const [uncontrolled, setUncontrolled] = useState(Boolean(props.defaultChecked));
  const checked = controlled ? Boolean(props.checked) : uncontrolled;
  const disabled = Boolean(props.disabled || props.loading);
  const sizeClass =
    props.size === 'small' || props.size === 'mini' || props.size === 'sm'
      ? 'arco-switch-small'
      : props.size === 'large' || props.size === 'lg'
        ? 'arco-switch-large'
        : '';

  return (
    <button
      type="button"
      id={props.id}
      role="switch"
      aria-checked={checked}
      aria-label={props['aria-label']}
      disabled={disabled}
      className={`arco-switch ${checked ? 'arco-switch-checked' : ''} ${sizeClass} ${props.className || ''}`.trim()}
      data-state={checked ? 'checked' : 'unchecked'}
      onClick={(event) => {
        // Prevent parent <label> from re-activating the control (double toggle).
        event.preventDefault();
        event.stopPropagation();
        if (disabled) return;
        const next = !checked;
        if (!controlled) setUncontrolled(next);
        props.onChange?.(next);
      }}
    >
      <span className="arco-switch-dot" aria-hidden="true" />
      {checked ? props.checkedText : props.uncheckedText}
    </button>
  );
}

export function Checkbox(props: {
  checked?: boolean;
  defaultChecked?: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onChange?(checked: any): void;
  disabled?: boolean;
  children?: ReactNode;
  value?: string | number;
  className?: string;
  [key: string]: unknown;
}) {
  return (
    <label className={`inline-flex items-center gap-2 text-sm ${props.className || ''}`.trim()}>
      <AppicaCheckbox
        checked={props.checked}
        defaultChecked={props.defaultChecked}
        disabled={props.disabled}
        onCheckedChange={(checked) => props.onChange?.(Boolean(checked))}
      />
      {props.children}
    </label>
  );
}

Checkbox.Group = function CheckboxGroup(props: {
  value?: Array<string | number>;
  defaultValue?: Array<string | number>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onChange?(value: any): void;
  options?: Array<{ label: ReactNode; value: string | number }>;
  children?: ReactNode;
  className?: string;
  direction?: string;
  [key: string]: unknown;
}) {
  const selected = new Set((props.value || props.defaultValue || []).map(String));
  const options =
    props.options ||
    Children.toArray(props.children)
      .filter(isValidElement)
      .map((child) => {
        const el = child as ReactElement<{ value?: string | number; children?: ReactNode }>;
        return { label: el.props.children, value: el.props.value ?? '' };
      });

  return (
    <div className={`flex flex-wrap gap-3 ${props.className || ''}`.trim()}>
      {options.map((option) => {
        const key = String(option.value);
        const checked = selected.has(key);
        return (
          <Checkbox
            key={key}
            checked={checked}
            onChange={(next) => {
              const copy = new Set(selected);
              if (next) copy.add(key);
              else copy.delete(key);
              props.onChange?.(Array.from(copy));
            }}
          >
            {option.label}
          </Checkbox>
        );
      })}
    </div>
  );
};

export function Radio(props: { value?: string; children?: ReactNode; [key: string]: unknown }) {
  return <span data-radio-value={props.value}>{props.children}</span>;
}

Radio.Group = function RadioGroup(props: {
  value?: string;
  defaultValue?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onChange?(value: any): void;
  options?: Array<{ label: ReactNode; value: string }>;
  children?: ReactNode;
  type?: string;
  className?: string;
  size?: string;
  name?: string;
  [key: string]: unknown;
}) {
  const options =
    props.options ||
    Children.toArray(props.children)
      .filter(isValidElement)
      .map((child) => {
        const el = child as ReactElement<{ value?: string; children?: ReactNode }>;
        return { label: el.props.children, value: el.props.value || '' };
      });

  return (
    <div className={`arco-radio-group inline-flex flex-wrap gap-2 ${props.className || ''}`.trim()}>
      {options.map((option) => {
        const active = props.value === option.value;
        return (
          <Button
            key={option.value}
            size="sm"
            type={active ? 'primary' : 'outline'}
            htmlType="button"
            className={active ? 'arco-radio-button arco-radio-button-checked arco-radio-checked' : 'arco-radio-button'}
            onClick={() => props.onChange?.(option.value)}
          >
            {option.label}
          </Button>
        );
      })}
    </div>
  );
};

type TableColumn<T> = {
  title?: ReactNode;
  dataIndex?: string;
  key?: string;
  width?: number | string;
  // method form = bivariant; page columns use (value: string) etc.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  render?(value: any, record: any, index: number): ReactNode;
  sorter?: boolean | ((a: T, b: T) => number);
  align?: string;
  ellipsis?: boolean;
  fixed?: string | boolean;
  [key: string]: unknown;
};

export function Table<T = Record<string, unknown>>(props: {
  columns?: Array<TableColumn<T>>;
  data?: T[];
  dataSource?: T[];
  rowKey?: string | ((record: T) => string);
  loading?: boolean;
  pagination?:
    | false
    | {
        current?: number;
        pageSize?: number;
        total?: number;
        onChange?: (page: number, pageSize?: number) => void;
        sizeCanChange?: boolean;
        showTotal?: boolean | ((total: number, range?: [number, number]) => ReactNode);
        pageSizeChangeResetCurrent?: boolean;
        sizeOptions?: number[];
        simple?: boolean;
        hideOnSinglePage?: boolean;
        bufferSize?: number;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        [key: string]: any;
      };
  className?: string;
  size?: string;
  scroll?: { x?: number | string; y?: number | string };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onRow?: (record: any, index?: number) => any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  rowClassName?: string | ((record: any, index?: number) => string);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  expandedRowRender?: (record: any, index?: number) => ReactNode;
  rowSelection?: unknown;
  border?: boolean;
  hover?: boolean;
  noDataElement?: ReactNode;
  [key: string]: unknown;
}) {
  const allRows = (props.dataSource || props.data || []) as T[];
  const columns = props.columns || [];
  const paginationConfig = props.pagination;
  const paginate = paginationConfig !== false && paginationConfig != null && typeof paginationConfig === 'object';

  const [innerPage, setInnerPage] = useState(1);
  const [innerPageSize, setInnerPageSize] = useState(
    paginate && typeof paginationConfig.pageSize === 'number' ? paginationConfig.pageSize : 10,
  );

  // sizeCanChange keeps page size local (Arco default); otherwise honor explicit pageSize.
  const pageSize = paginate
    ? paginationConfig.sizeCanChange
      ? innerPageSize
      : paginationConfig.pageSize ?? innerPageSize
    : allRows.length || 1;
  const total = paginate && paginationConfig.total != null ? paginationConfig.total : allRows.length;
  // Server-side: parent supplies current page slice + total + onChange.
  const serverSide =
    paginate && typeof paginationConfig.onChange === 'function' && paginationConfig.total != null;
  const currentRaw = paginate && paginationConfig.current != null ? paginationConfig.current : innerPage;
  const pageCount = Math.max(1, Math.ceil((total || 0) / Math.max(1, pageSize)));
  const current = Math.min(Math.max(1, currentRaw), pageCount);

  const rows = paginate && !serverSide
    ? allRows.slice((current - 1) * pageSize, current * pageSize)
    : allRows;

  const showPager =
    paginate &&
    !(paginationConfig.hideOnSinglePage && pageCount <= 1) &&
    (total > 0 || allRows.length > 0);

  const changePage = (page: number, nextSize = pageSize) => {
    if (!paginate) return;
    const sizeChanged = nextSize !== pageSize;
    // Arco resets to page 1 on pageSize change unless pageSizeChangeResetCurrent === false.
    const nextPage =
      sizeChanged && paginationConfig.pageSizeChangeResetCurrent !== false ? 1 : page;
    if (paginationConfig.current == null) {
      setInnerPage(nextPage);
    }
    if (paginationConfig.sizeCanChange || paginationConfig.pageSize == null) {
      setInnerPageSize(nextSize);
    }
    paginationConfig.onChange?.(nextPage, nextSize);
  };

  if (props.loading) {
    return (
      <div className="flex justify-center py-10">
        <Spinner />
      </div>
    );
  }

  const emptyContent = props.noDataElement ?? (
    <span className="text-foreground-muted">No data</span>
  );

  return (
    <div className={`arco-table arco-table-container w-full overflow-auto ${props.className || ''}`.trim()}>
      <AppicaTable hoverableRows className="arco-table-element">
        <TableHeader>
          <TableRow className="arco-table-tr">
            {columns.map((column, index) => (
              <TableHead
                key={String(column.key || column.dataIndex || index)}
                className="arco-table-th"
                style={{ width: column.width }}
              >
                {column.title}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody className="arco-table-body">
          {rows.length === 0 ? (
            <TableRow className="arco-table-tr">
              <TableCell
                colSpan={Math.max(columns.length, 1)}
                className="arco-table-td arco-table-cell text-center text-foreground-muted"
              >
                {emptyContent}
              </TableCell>
            </TableRow>
          ) : (
            rows.map((record, rowIndex) => {
              const absoluteIndex = paginate && !serverSide ? (current - 1) * pageSize + rowIndex : rowIndex;
              const key =
                typeof props.rowKey === 'function'
                  ? props.rowKey(record)
                  : String((record as Record<string, unknown>)[props.rowKey || 'id'] ?? absoluteIndex);
              const rowProps = props.onRow?.(record, absoluteIndex) || {};
              const {
                className: rowPropsClassName,
                onClick: rowOnClick,
                onKeyDown: rowOnKeyDown,
                ...restRowProps
              } = rowProps as {
                className?: string;
                onClick?: (event: unknown) => void;
                onKeyDown?: (event: unknown) => void;
                [key: string]: unknown;
              };
              const classFromProp =
                typeof props.rowClassName === 'function'
                  ? props.rowClassName(record, absoluteIndex)
                  : props.rowClassName;
              const rowClassName =
                ['arco-table-tr', classFromProp, rowPropsClassName].filter(Boolean).join(' ') || undefined;
              return (
                <TableRow
                  key={key}
                  className={rowClassName}
                  onClick={(event) => rowOnClick?.(event)}
                  onKeyDown={(event) => rowOnKeyDown?.(event)}
                  {...(restRowProps as object)}
                >
                  {columns.map((column, colIndex) => {
                    const raw = column.dataIndex ? (record as Record<string, unknown>)[column.dataIndex] : undefined;
                    const content = column.render ? column.render(raw, record, absoluteIndex) : (raw as ReactNode);
                    return (
                      <TableCell
                        key={String(column.key || column.dataIndex || colIndex)}
                        className="arco-table-td arco-table-cell"
                      >
                        {content}
                      </TableCell>
                    );
                  })}
                </TableRow>
              );
            })
          )}
        </TableBody>
      </AppicaTable>
      {showPager ? (
        <div className="mt-3 flex flex-wrap items-center justify-end gap-2 text-sm">
          {paginationConfig.showTotal ? (
            <span className="mr-auto text-foreground-muted">
              {typeof paginationConfig.showTotal === 'function'
                ? paginationConfig.showTotal(total, [
                    total === 0 ? 0 : (current - 1) * pageSize + 1,
                    Math.min(current * pageSize, total),
                  ])
                : `Total ${total}`}
            </span>
          ) : null}
          {paginationConfig.sizeCanChange ? (
            <select
              className="rounded border border-border bg-background px-2 py-1 text-sm"
              value={pageSize}
              aria-label="Page size"
              onChange={(event) => {
                const nextSize = Number(event.target.value) || pageSize;
                changePage(1, nextSize);
              }}
            >
              {(paginationConfig.sizeOptions || [10, 20, 50, 100]).map((size) => (
                <option key={size} value={size}>
                  {size} / page
                </option>
              ))}
            </select>
          ) : null}
          <Button size="sm" type="outline" disabled={current <= 1} onClick={() => changePage(current - 1)}>
            Prev
          </Button>
          <span>
            {current} / {pageCount}
          </span>
          <Button size="sm" type="outline" disabled={current >= pageCount} onClick={() => changePage(current + 1)}>
            Next
          </Button>
        </div>
      ) : null}
    </div>
  );
}

export function Tabs(props: {
  activeTab?: string;
  defaultActiveTab?: string;
  onChange?: (key: string) => void;
  children?: ReactNode;
  className?: string;
  type?: string;
  size?: string;
  [key: string]: unknown;
}) {
  // Do NOT use Children.toArray — it rewrites keys (e.g. "entries" → ".$entries")
  // and breaks controlled activeTab matching.
  const panes = (
    Array.isArray(props.children) ? props.children : props.children != null ? [props.children] : []
  ).filter(isValidElement) as Array<ReactElement<{ title?: ReactNode; children?: ReactNode; tabKey?: string }>>;

  const keys = panes.map((pane, index) => String(pane.key ?? pane.props.tabKey ?? index));
  const fallback = props.defaultActiveTab || keys[0] || '0';
  const [uncontrolled, setUncontrolled] = useState(fallback);
  const controlled = props.activeTab !== undefined && props.activeTab !== null;
  const value = controlled ? String(props.activeTab) : uncontrolled;

  return (
    <AppicaTabs
      value={value}
      onValueChange={(next) => {
        const key = String(next);
        if (!controlled) setUncontrolled(key);
        props.onChange?.(key);
      }}
      className={`arco-tabs ${props.className || ''}`.trim()}
    >
      <TabsList className="arco-tabs-header arco-tabs-header-nav">
        {panes.map((pane, index) => {
          const key = keys[index];
          const active = value === key;
          return (
            <TabsTrigger
              key={key}
              value={key}
              className={`arco-tabs-header-title ${active ? 'arco-tabs-header-title-active' : ''}`.trim()}
            >
              {pane.props.title || key}
            </TabsTrigger>
          );
        })}
      </TabsList>
      {panes.map((pane, index) => {
        const key = keys[index];
        return (
          // keepMounted: Arco kept inactive panes in the tree; tests and forms
          // that read values from non-active tabs rely on this.
          <TabsContent key={key} value={key} keepMounted className="arco-tabs-content">
            {pane.props.children}
          </TabsContent>
        );
      })}
    </AppicaTabs>
  );
}

Tabs.TabPane = function TabPane(_props: {
  title?: ReactNode;
  children?: ReactNode;
  key?: string;
  tabKey?: string;
}) {
  return null;
};

export function Tooltip(props: {
  content?: ReactNode;
  children?: ReactNode;
  className?: string;
  position?: string;
  disabled?: boolean;
  [key: string]: unknown;
}) {
  if (props.disabled) {
    return <>{props.children}</>;
  }
  return (
    <AppicaTooltip>
      <TooltipTrigger render={<span className={props.className} />}>{props.children}</TooltipTrigger>
      <TooltipContent>{props.content}</TooltipContent>
    </AppicaTooltip>
  );
}

export function Dropdown(props: {
  droplist?: ReactNode;
  position?: string;
  children?: ReactNode;
  trigger?: string | string[];
  unmountOnExit?: boolean;
  disabled?: boolean;
  [key: string]: unknown;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<span />}>{props.children}</DropdownMenuTrigger>
      <DropdownMenuContent>{props.droplist}</DropdownMenuContent>
    </DropdownMenu>
  );
}

export function Menu(props: {
  children?: ReactNode;
  onClickMenuItem?: (key: string) => void;
  selectedKeys?: string[];
  className?: string;
  [key: string]: unknown;
}) {
  return (
    <div className={`flex flex-col gap-0.5 p-1 ${props.className || ''}`.trim()}>
      {Children.map(props.children, (child) => {
        if (!isValidElement(child)) return child;
        const el = child as ReactElement<{ key?: string; children?: ReactNode; onClick?: () => void }>;
        const key = String(el.key || '');
        return (
          <DropdownMenuItem
            key={key}
            onClick={() => {
              props.onClickMenuItem?.(key);
              el.props.onClick?.();
            }}
          >
            {el.props.children}
          </DropdownMenuItem>
        );
      })}
    </div>
  );
}

Menu.Item = function MenuItem(props: { key?: string; children?: ReactNode; onClick?: () => void; [key: string]: unknown }) {
  return (
    <button type="button" onClick={props.onClick}>
      {props.children}
    </button>
  );
};

export function Popover(props: {
  content?: ReactNode;
  children?: ReactNode;
  trigger?: string;
  position?: string;
  [key: string]: unknown;
}) {
  return (
    <AppicaPopover>
      <PopoverTrigger render={<span />}>{props.children}</PopoverTrigger>
      <PopoverContent>{props.content}</PopoverContent>
    </AppicaPopover>
  );
}

export function Popconfirm(props: {
  title?: ReactNode;
  content?: ReactNode;
  onOk?: () => void | Promise<void>;
  onConfirm?: () => void | Promise<void>;
  children?: ReactNode;
  okButtonProps?: { status?: string };
  okText?: string;
  cancelText?: string;
  [key: string]: unknown;
}) {
  return (
    <span
      onClick={(event) => {
        event.preventDefault();
        event.stopPropagation();
        confirm({
          title: String(props.title || 'Confirm'),
          content: props.content ? String(props.content) : undefined,
          okButtonProps: props.okButtonProps,
          okText: props.okText,
          cancelText: props.cancelText,
          onOk: props.onOk || props.onConfirm,
        });
      }}
    >
      {props.children}
    </span>
  );
}

export function Steps(props: {
  current?: number;
  children?: ReactNode;
  className?: string;
  size?: string;
  direction?: string;
  [key: string]: unknown;
}) {
  const items = Children.toArray(props.children).filter(isValidElement) as Array<
    ReactElement<{ title?: ReactNode; description?: ReactNode }>
  >;
  return (
    <ol className={`flex flex-wrap gap-4 ${props.className || ''}`.trim()}>
      {items.map((item, index) => {
        const active = (props.current || 0) === index;
        const done = (props.current || 0) > index;
        return (
          <li
            key={index}
            className={`flex min-w-[8rem] flex-col gap-1 ${active ? 'text-foreground-intense' : 'text-foreground-muted'}`}
          >
            <span className={`text-xs font-semibold ${done || active ? 'text-primary' : ''}`}>
              {index + 1}. {item.props.title}
            </span>
            {item.props.description ? <span className="text-xs">{item.props.description}</span> : null}
          </li>
        );
      })}
    </ol>
  );
}

Steps.Step = function Step(_props: {
  title?: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  status?: string;
  [key: string]: unknown;
}) {
  return null;
};

export function DatePicker(props: {
  value?: string | Date | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onChange?: (...args: any[]) => void;
  style?: CSSProperties;
  className?: string;
  showTime?: boolean | object;
  format?: string;
  placeholder?: string;
  allowClear?: boolean;
  disabled?: boolean;
  [key: string]: unknown;
}) {
  const value =
    props.value instanceof Date
      ? props.value.toISOString().slice(0, props.showTime ? 16 : 10)
      : props.value
        ? String(props.value).slice(0, props.showTime ? 16 : 10)
        : '';
  return (
    <Input
      type={props.showTime ? 'datetime-local' : 'date'}
      value={value}
      className={props.className}
      style={props.style}
      placeholder={props.placeholder}
      disabled={props.disabled}
      onChange={(next) => props.onChange?.(next || undefined, next || undefined)}
    />
  );
}

DatePicker.RangePicker = function RangePicker(props: {
  value?: [string, string] | string[] | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onChange?: (...args: any[]) => void;
  className?: string;
  style?: CSSProperties;
  showTime?: boolean | object;
  format?: string;
  allowClear?: boolean;
  [key: string]: unknown;
}) {
  const start = props.value?.[0] || '';
  const end = props.value?.[1] || '';
  const inputType = props.showTime ? 'datetime-local' : 'date';
  return (
    <div className={`inline-flex items-center gap-2 ${props.className || ''}`.trim()} style={props.style}>
      <Input
        type={inputType}
        value={start}
        onChange={(next) => props.onChange?.([String(next || ''), end], [String(next || ''), end])}
      />
      <span className="text-foreground-muted">–</span>
      <Input
        type={inputType}
        value={end}
        onChange={(next) => props.onChange?.([start, String(next || '')], [start, String(next || '')])}
      />
    </div>
  );
};

export function Pagination(props: {
  current?: number;
  pageSize?: number;
  total?: number;
  onChange?: (page: number, pageSize?: number) => void;
  simple?: boolean;
  size?: string;
  className?: string;
  showTotal?: boolean | ((total: number, range: [number, number]) => ReactNode);
  sizeCanChange?: boolean;
  sizeOptions?: number[];
  [key: string]: unknown;
}) {
  const current = props.current || 1;
  const pageSize = props.pageSize || 10;
  const total = props.total || 0;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const range: [number, number] = [Math.min((current - 1) * pageSize + 1, total), Math.min(current * pageSize, total)];
  const sizeOptions = props.sizeOptions || [10, 20, 50, 100];
  return (
    <div className={`flex flex-wrap items-center gap-2 text-sm ${props.className || ''}`.trim()}>
      <Button size="sm" type="outline" disabled={current <= 1} onClick={() => props.onChange?.(current - 1, pageSize)}>
        Prev
      </Button>
      <span>
        {current} / {pages}
      </span>
      <Button size="sm" type="outline" disabled={current >= pages} onClick={() => props.onChange?.(current + 1, pageSize)}>
        Next
      </Button>
      {props.sizeCanChange ? (
        <label className="inline-flex items-center gap-1 text-foreground-muted">
          <span className="sr-only">Page size</span>
          <select
            className="rounded border border-border bg-background px-1.5 py-1 text-sm text-foreground"
            value={pageSize}
            aria-label="Page size"
            onChange={(event) => {
              const nextSize = Number(event.target.value);
              if (!Number.isFinite(nextSize) || nextSize <= 0) return;
              // Arco: changing page size typically resets to page 1.
              props.onChange?.(1, nextSize);
            }}
          >
            {sizeOptions.map((size) => (
              <option key={size} value={size}>
                {size} / page
              </option>
            ))}
          </select>
        </label>
      ) : null}
      {props.showTotal ? (
        <span className="text-foreground-muted">
          {typeof props.showTotal === 'function' ? props.showTotal(total, range) : `Total ${total}`}
        </span>
      ) : null}
    </div>
  );
}

export function Progress(props: {
  percent?: number;
  className?: string;
  size?: string;
  status?: string;
  showText?: boolean;
  [key: string]: unknown;
}) {
  return <AppicaProgress value={props.percent || 0} className={props.className} />;
}

export function Skeleton(props: {
  loading?: boolean;
  children?: ReactNode;
  animation?: boolean;
  text?: unknown;
  image?: unknown;
  [key: string]: unknown;
}) {
  if (props.loading === false) {
    return <>{props.children}</>;
  }
  if (props.children && props.loading !== true) {
    // Arco Skeleton with loading undefined often still shows children when not loading
  }
  if (props.loading === undefined && props.children) {
    return <>{props.children}</>;
  }
  return <AppicaSkeleton className="h-24 w-full" />;
}

export function Tag(props: {
  children?: ReactNode;
  color?: string;
  className?: string;
  size?: string;
  bordered?: boolean;
  icon?: ReactNode;
  closable?: boolean;
  onClose?: () => void;
  [key: string]: unknown;
}) {
  return (
    <Badge className={`arco-tag ${props.className || ''}`.trim()}>
      {props.icon}
      <span className="arco-tag-content">{props.children}</span>
    </Badge>
  );
}

export function Spin(props: {
  loading?: boolean;
  children?: ReactNode;
  className?: string;
  size?: number | string;
  tip?: ReactNode;
  [key: string]: unknown;
}) {
  if (props.loading === false) {
    return <>{props.children}</>;
  }
  if (props.children && props.loading) {
    return (
      <div className={`arco-spin arco-spin-loading relative ${props.className || ''}`.trim()}>
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center bg-background/50">
          <Spinner />
        </div>
        {props.children}
      </div>
    );
  }
  if (props.children && props.loading === undefined) {
    return <>{props.children}</>;
  }
  return (
    <div className={`arco-spin arco-spin-loading flex justify-center py-6 ${props.className || ''}`.trim()}>
      <Spinner />
    </div>
  );
}

export function Empty(props: { description?: ReactNode; className?: string; imgSrc?: string; [key: string]: unknown }) {
  return (
    <div
      className={`arco-empty flex flex-col items-center justify-center gap-2 py-10 text-sm text-foreground-muted ${props.className || ''}`.trim()}
    >
      <span className="arco-empty-description">{props.description || 'No data'}</span>
    </div>
  );
}

export function Space(props: {
  children?: ReactNode;
  className?: string;
  direction?: 'horizontal' | 'vertical';
  size?: number | string;
  wrap?: boolean;
  align?: string;
  [key: string]: unknown;
}) {
  const direction = props.direction === 'vertical' ? 'flex-col' : 'flex-row';
  const wrap = props.wrap ? 'flex-wrap' : '';
  return (
    <div className={`arco-space inline-flex items-center gap-2 ${direction} ${wrap} ${props.className || ''}`.trim()}>
      {props.children}
    </div>
  );
}

export function Card(props: {
  children?: ReactNode;
  className?: string;
  title?: ReactNode;
  extra?: ReactNode;
  bordered?: boolean;
  size?: string;
  [key: string]: unknown;
}) {
  return (
    <section className={`rounded-xl border border-border bg-background p-4 shadow-sm ${props.className || ''}`.trim()}>
      {props.title || props.extra ? (
        <header className="mb-3 flex items-center justify-between gap-2">
          <div className="text-base font-semibold text-foreground-intense">{props.title}</div>
          {props.extra ? <div>{props.extra}</div> : null}
        </header>
      ) : null}
      {props.children}
    </section>
  );
}

export const Typography = {
  Title: ({
    children,
    heading = 4,
    className = '',
  }: {
    children?: ReactNode;
    heading?: number;
    className?: string;
    [key: string]: unknown;
  }) => {
    const size = heading <= 2 ? 'text-2xl' : heading === 3 ? 'text-xl' : heading === 4 ? 'text-lg' : 'text-base';
    return <h2 className={`${size} font-semibold text-foreground-intense ${className}`.trim()}>{children}</h2>;
  },
  Paragraph: ({ children, className = '', ..._rest }: { children?: ReactNode; className?: string; [key: string]: unknown }) => (
    <p className={`text-sm text-foreground-muted ${className}`.trim()}>{children}</p>
  ),
  Text: ({
    children,
    className = '',
    type,
    ..._rest
  }: {
    children?: ReactNode;
    className?: string;
    type?: string;
    [key: string]: unknown;
  }) => <span className={`${type === 'secondary' ? 'text-foreground-muted' : ''} ${className}`.trim()}>{children}</span>,
};

export function Modal(props: {
  visible?: boolean;
  open?: boolean;
  title?: ReactNode;
  children?: ReactNode;
  onCancel?: () => void;
  onOk?: () => void | Promise<void>;
  confirmLoading?: boolean;
  okText?: string;
  cancelText?: string;
  footer?: ReactNode | null;
  style?: CSSProperties;
  className?: string;
  unmountOnExit?: boolean;
  maskClosable?: boolean;
  closable?: boolean;
  okButtonProps?: { status?: string; disabled?: boolean };
  simple?: boolean;
  'aria-label'?: string;
  [key: string]: unknown;
}) {
  const open = props.visible ?? props.open ?? false;
  if (!open) {
    return null;
  }

  // Lightweight overlay (not Base UI Dialog): keeps the page tree in the a11y tree
  // so gates/controls behind the modal remain queryable — matches prior Arco behavior used by tests.
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      role="presentation"
      onClick={() => {
        if (props.maskClosable !== false) props.onCancel?.();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={props['aria-label'] || (typeof props.title === 'string' ? props.title : undefined)}
        className={`arco-modal max-h-[90vh] w-full max-w-lg overflow-auto rounded-xl border border-border bg-background p-4 shadow-xl ${props.className || ''}`.trim()}
        style={props.style}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="arco-modal-content">
          {props.title ? (
            <header className="arco-modal-header mb-3 text-base font-semibold text-foreground-intense">{props.title}</header>
          ) : null}
          <div className="arco-modal-body">{props.children}</div>
          {props.footer === null ? null : props.footer !== undefined ? (
            <div className="arco-modal-footer mt-4 flex justify-end gap-2">{props.footer}</div>
          ) : (
            <div className="arco-modal-footer mt-4 flex justify-end gap-2">
              <Button type="outline" onClick={() => props.onCancel?.()}>
                {props.cancelText || 'Cancel'}
              </Button>
              <Button
                type="primary"
                status={props.okButtonProps?.status}
                loading={props.confirmLoading}
                disabled={props.okButtonProps?.disabled}
                onClick={() => void props.onOk?.()}
              >
                {props.okText || 'OK'}
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

Modal.confirm = (options: ConfirmOptions) => confirm(options);

export { Message };
export { confirm };
