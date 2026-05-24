import type { Transition } from 'framer-motion';

export const fastSpring: Transition = {
  type: 'spring',
  stiffness: 420,
  damping: 34,
  mass: 0.8,
};

export const softFade: Transition = {
  duration: 0.2,
  ease: 'easeOut',
};
