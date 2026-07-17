//go:build captchae2e

package captcha

import (
	"reflect"
	"testing"
)

func TestBuildE2EBehaviorPlanMatchesBrowserHarnessAndVerifier(t *testing.T) {
	state, err := newBrowserHarnessState()
	if err != nil {
		t.Fatal("E2E plan fixture initialization failed")
	}
	for _, scenario := range browserHarnessScenarios {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			for _, variant := range []string{"wrong", "correct"} {
				fixture, _, issueErr := state.issue(scenario.Name)
				if issueErr != nil {
					t.Fatalf("issue %s: %v", variant, issueErr)
				}
				got, planErr := BuildE2EBehaviorPlan(fixture.opts, fixture.challenge, variant)
				if planErr != nil {
					t.Fatalf("build %s plan: %v", variant, planErr)
				}
				wantPlan := makeBrowserHarnessPlan(fixture)
				wantAction := wantPlan.Wrong
				if variant == "correct" {
					wantAction = wantPlan.Correct
				}
				want := E2EBehaviorPlan{
					Interaction: wantPlan.Interaction,
					Action:      E2EBehaviorAction{Value: wantAction.Value, Path: wantAction.Path, At: wantAction.At},
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s plan mismatch: got=%+v want=%+v", variant, got, want)
				}
				response := browserHarnessResponse(fixture, got.Interaction, browserHarnessAction{
					Value: got.Action.Value,
					Path:  got.Action.Path,
					At:    got.Action.At,
				})
				result := VerifyBehaviorChallenge(harnessVerificationOptions(fixture.opts, response), response)
				if result.Valid != (variant == "correct") {
					t.Fatalf("%s verifier result=%+v", variant, result)
				}
			}
		})
	}
}

func TestBuildE2EBehaviorPlanRejectsInvalidControlInputs(t *testing.T) {
	state, err := newBrowserHarnessState()
	if err != nil {
		t.Fatal("E2E plan fixture initialization failed")
	}
	fixture, _, err := state.issue("rotate")
	if err != nil {
		t.Fatal("E2E plan fixture issue failed")
	}
	if _, err = BuildE2EBehaviorPlan(fixture.opts, fixture.challenge, "maybe"); err == nil {
		t.Fatal("invalid variant was accepted")
	}
	tampered := fixture.challenge
	tampered.Type = BehaviorScratch
	if _, err = BuildE2EBehaviorPlan(fixture.opts, tampered, "correct"); err == nil {
		t.Fatal("challenge type mismatch was accepted")
	}
}
