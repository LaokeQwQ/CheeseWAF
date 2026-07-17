import type { SelectionChallengeProps } from "./SelectionChallenge";
import { SelectionChallenge } from "./SelectionChallenge";
export type IconClickChallengeProps = Omit<SelectionChallengeProps, "testId">;
export function IconClickChallenge(props: IconClickChallengeProps) { return <SelectionChallenge {...props} testId="icon-click-challenge"/>; }
