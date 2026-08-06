/**
 * Admin design-system surface.
 * Pages should import from here (Arco-compatible helpers + Appica primitives).
 */

export {
  Button,
  Input,
  Form,
  useForm,
  Select,
  InputNumber,
  Switch,
  Checkbox,
  Radio,
  Table,
  Tabs,
  Tooltip,
  Dropdown,
  Menu,
  Popover,
  Popconfirm,
  Steps,
  DatePicker,
  Pagination,
  Progress,
  Skeleton,
  Tag,
  Spin,
  Empty,
  Space,
  Card,
  Typography,
  Message,
  Modal,
  confirm,
} from './arco-compat';

export { Form as default } from './arco-compat';
export { default as ToastHost } from './ToastHost';

// Direct Appica re-exports for new code
export { Field, FieldLabel, FieldDescription, FieldError } from '@appica/ui-react/field';
export { ThemeProvider } from '@appica/ui-react/providers/theme-provider';
export { Badge } from '@appica/ui-react/badge';
export { Spinner } from '@appica/ui-react/spinner';
export { Navigation, NavigationList, NavigationItem, NavigationLink } from '@appica/ui-react/navigation';
export {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogClose,
} from '@appica/ui-react/dialog';
export {
  Drawer,
  DrawerTrigger,
  DrawerContent,
  DrawerHeader,
  DrawerTitle,
  DrawerDescription,
} from '@appica/ui-react/drawer';
