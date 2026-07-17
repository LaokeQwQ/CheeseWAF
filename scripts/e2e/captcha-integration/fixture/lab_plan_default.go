//go:build !captchae2e

package main

import (
	"errors"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
)

func (fx *fixture) labPlan(captcha.BehaviorChallenge, string) (any, error) {
	return nil, errors.New("CAPTCHA Lab E2E plan helper is not built")
}
