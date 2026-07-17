import type { SelectionChallengeProps } from "./SelectionChallenge";
import { SelectionChallenge } from "./SelectionChallenge";
export type TextClickChallengeProps = Omit<SelectionChallengeProps, "testId">;
export function TextClickChallenge(props: TextClickChallengeProps) { return <SelectionChallenge {...props} testId="text-click-challenge"/>; }
