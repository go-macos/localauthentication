// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package localauthentication

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// The one test that really prompts.
//
// It is skipped unless a person sets LOCALAUTH_LIVE_PROMPT=1, because a test
// suite that puts a Touch ID sheet in front of whoever typed `go test` is a
// test suite people learn to stop running — and because CI has no finger to
// offer. Everything the rest of the suite proves, it proves without asking
// anyone for anything.
//
// What this adds that nothing else can: whether the sheet ACTUALLY APPEARS,
// with the right words on it, and what the framework says when a real person
// touches the sensor, presses Cancel, or presses "Use Password…". That is not
// something a seam can stand in for, and no amount of green CI is evidence of
// it.
//
// Run it from inside a real .app bundle for the result that matters. Built with
// github.com/go-macos/appbundle, the prompt reads «YourApp» is trying to
// confirm you are at this Mac. Run as a bare `go test` binary it may well be
// refused before any sheet is drawn — which is itself worth seeing once, and
// is what [ErrNotBundled] exists to explain.
//
//	LOCALAUTH_LIVE_PROMPT=1 go test -run TestLivePrompt -v
func TestLivePrompt(t *testing.T) {
	if os.Getenv("LOCALAUTH_LIVE_PROMPT") != "1" {
		t.Skip("set LOCALAUTH_LIVE_PROMPT=1 to be prompted for real")
	}

	t.Logf("bundle identifier: %q (unbundled=%v)", bundleIdentifier(), platformUnbundled())
	kind, err := Biometry()
	if err != nil {
		t.Fatalf("Biometry: %v", err)
	}
	t.Logf("biometry: %v", kind)
	t.Logf("Available(biometrics): %v", Available(PolicyBiometrics))
	t.Logf("Available(biometrics-or-password): %v", Available(PolicyOwner))

	// A minute is long enough to read the sheet and decide, and short enough
	// that a forgotten run does not sit there for the rest of the day. When it
	// expires the context is invalidated, which dismisses the sheet.
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	err = Evaluate(ctx, PolicyOwner, "confirm you are at this Mac")
	switch {
	case err == nil:
		t.Log("AUTHENTICATED")
	case errors.Is(err, ErrUserCancel):
		t.Log("the user pressed Cancel — a decision, and not a test failure")
	case errors.Is(err, ErrUserFallback):
		t.Log("the user asked for a password")
	case errors.Is(err, ErrNotBundled):
		t.Logf("refused, and this process is not an .app bundle: %v", err)
	default:
		t.Logf("refused: %v", err)
	}
	var e *Error
	if errors.As(err, &e) {
		t.Logf("raw LAError %d: %q", e.Code, e.Message)
	}
}
