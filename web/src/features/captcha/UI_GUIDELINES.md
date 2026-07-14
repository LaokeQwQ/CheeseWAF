# CAPTCHA UI Guidelines

These rules apply to login challenges, WAF client challenges, and CAPTCHA Lab.

## Geometry

- Challenge shell: `8px` radius, one-pixel neutral border, restrained shadow.
- Media stage: `6px` radius and `overflow: hidden`; preserve the source aspect ratio.
- Slider track and primary confirmation button: `6px` radius and at least `40px` high.
- Slider thumb and icon-only actions: circular, at least `40px` by `40px` on touch devices.
- Footer logo: `28px` visual size with a `40px` interaction target.
- Refresh and close actions: same visual and interaction size, aligned on one baseline.

## States And Motion

- Loading: use a low-contrast skeleton in the media stage. Never show a blank rectangle.
- Ready: reveal the challenge with a `160-220ms` opacity transition.
- Interacting: animate only the controlled object and progress feedback.
- Verifying: freeze input and show an inline progress state without resizing the shell.
- Success: use a green status surface and freeze the challenge.
- Incorrect answer: use an orange status surface, disable input, then issue a new challenge after `1000ms`.
- Service failure: use a red status surface and keep an explicit retry action. Do not treat it as an incorrect answer.
- All repeated submissions require a synchronous request lock in addition to React state.

## Accessibility

- Every icon action needs an accessible name and visible keyboard focus.
- Status changes use `aria-live=polite`; service failures use `role=alert`.
- Pointer interactions need keyboard or accessible alternatives where the challenge type permits them.
- Under `prefers-reduced-motion: reduce`, remove decorative motion and replace continuous rotation with a static progress indicator.
- Do not encode success, failure, or the requested target using color alone.

## Responsive Behavior

- Keep the challenge geometry stable; scale the complete stage instead of independently stretching its layers.
- Do not remove borders, radius, or padding on mobile. Reduce outer spacing while preserving the same component language.
- Use pointer capture for drag interactions and handle release outside the original control.
- A verified challenge cannot be reopened until the surrounding login or request action fails.
