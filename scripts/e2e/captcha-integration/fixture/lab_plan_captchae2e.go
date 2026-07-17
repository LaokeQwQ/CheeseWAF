//go:build captchae2e

package main

import "github.com/LaokeQwQ/CheeseWAF/internal/captcha"

func (fx *fixture) labPlan(challenge captcha.BehaviorChallenge, variant string) (any, error) {
	return captcha.BuildE2EBehaviorPlan(captcha.BehaviorOptions{
		Secret:    fx.secret,
		Purpose:   "admin-captcha-lab",
		ClientKey: fixtureAdminUserID + "\n" + fx.username,
		Path:      "/api/captcha/lab",
		Site:      "admin-console",
		Type:      captcha.BehaviorRandom,
	}, challenge, variant)
}
