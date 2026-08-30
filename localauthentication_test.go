// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package localauthentication

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Not one test in this file, or in any other, asks a real Secure Enclave
// anything. The seams below stand in for LAContext entirely, so every branch of
// the portable logic runs on every platform — and no run of `go test` can put a
// Touch ID prompt in front of whoever started it.

// fakeContext is a scriptable laContext.
type fakeContext struct {
	canOK      bool
	canCode    int
	canMessage string
	canCalls   int

	biometry int

	// evaluate, when set, is called instead of the default (which replies
	// immediately with the scripted values). A nil evaluate that never replies
	// is how the cancellation path is driven.
	evaluate   func(policy int, reason string, reply func(bool, int, string))
	replyOK    bool
	replyCode  int
	replyMsg   string
	lastPolicy int
	lastReason string

	invalidated int
	released    int
}

func (f *fakeContext) CanEvaluate(policy int) (bool, int, string) {
	f.canCalls++
	f.lastPolicy = policy
	return f.canOK, f.canCode, f.canMessage
}

func (f *fakeContext) Biometry() int { return f.biometry }

func (f *fakeContext) Evaluate(policy int, reason string, reply func(bool, int, string)) {
	f.lastPolicy, f.lastReason = policy, reason
	if f.evaluate != nil {
		f.evaluate(policy, reason, reply)
		return
	}
	reply(f.replyOK, f.replyCode, f.replyMsg)
}

func (f *fakeContext) Invalidate() { f.invalidated++ }
func (f *fakeContext) Release()    { f.released++ }

// withFake points the package seams at fc (or at newErr, when the context
// cannot be built at all) and at a fixed unbundled answer, restoring both
// afterwards. It returns the options the entry point asked for, so an option
// test can see what reached the backend.
func withFake(t *testing.T, fc *fakeContext, newErr error, notBundled bool) *options {
	t.Helper()
	origNew, origUnbundled := newContext, unbundled
	t.Cleanup(func() { newContext, unbundled = origNew, origUnbundled })

	got := &options{}
	newContext = func(o options) (laContext, error) {
		*got = o
		if newErr != nil {
			return nil, newErr
		}
		return fc, nil
	}
	unbundled = func() bool { return notBundled }
	return got
}

// ---------------------------------------------------------------------------
// Biometry
// ---------------------------------------------------------------------------

func TestBiometryReportsTheSensor(t *testing.T) {
	fc := &fakeContext{biometry: int(BiometryTouchID)}
	withFake(t, fc, nil, false)

	got, err := Biometry()
	if err != nil {
		t.Fatalf("Biometry: %v", err)
	}
	if got != BiometryTouchID {
		t.Fatalf("Biometry = %v, want Touch ID", got)
	}
	// The whole point of the wrapper: biometryType is only populated after a
	// canEvaluatePolicy: call, so one must have been made.
	if fc.canCalls != 1 {
		t.Fatalf("CanEvaluate called %d times, want exactly 1 (biometryType is unset without it)", fc.canCalls)
	}
	if fc.lastPolicy != int(PolicyBiometrics) {
		t.Fatalf("primed with policy %d, want PolicyBiometrics", fc.lastPolicy)
	}
	if fc.released != 1 {
		t.Fatalf("Release called %d times, want 1", fc.released)
	}
}

func TestBiometryPropagatesContextFailure(t *testing.T) {
	withFake(t, nil, ErrUnavailable, false)
	got, err := Biometry()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Biometry error = %v, want ErrUnavailable", err)
	}
	if got != BiometryNone {
		t.Fatalf("Biometry = %v, want BiometryNone on failure", got)
	}
}

// ---------------------------------------------------------------------------
// Available
// ---------------------------------------------------------------------------

func TestAvailableSuccess(t *testing.T) {
	fc := &fakeContext{canOK: true}
	withFake(t, fc, nil, false)
	if err := Available(PolicyOwner); err != nil {
		t.Fatalf("Available = %v, want nil", err)
	}
	if fc.lastPolicy != int(PolicyOwner) {
		t.Fatalf("policy = %d, want PolicyOwner (2)", fc.lastPolicy)
	}
	if fc.released != 1 {
		t.Fatalf("Release called %d times, want 1", fc.released)
	}
}

func TestAvailableMapsTheReason(t *testing.T) {
	fc := &fakeContext{canCode: codeBiometryNotEnrolled, canMessage: "No fingerprint is enrolled."}
	withFake(t, fc, nil, false)

	err := Available(PolicyBiometrics)
	if !errors.Is(err, ErrBiometryNotEnrolled) {
		t.Fatalf("Available error = %v, want ErrBiometryNotEnrolled", err)
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("Available error = %v, want *Error", err)
	}
	if e.Op != "available" || e.Code != codeBiometryNotEnrolled || e.Message != "No fingerprint is enrolled." {
		t.Fatalf("Error = %+v", e)
	}
}

func TestAvailableWithoutAnNSError(t *testing.T) {
	// canEvaluatePolicy: answered NO and set no out-parameter. It should not
	// happen; it must still produce an error rather than a silent nil.
	fc := &fakeContext{}
	withFake(t, fc, nil, false)

	err := Available(PolicyBiometrics)
	var e *Error
	if !errors.As(err, &e) || e.Code != 0 {
		t.Fatalf("Available error = %v, want *Error with Code 0", err)
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("code 0 must not unwrap to a sentinel, got %v", errors.Unwrap(err))
	}
}

func TestAvailablePropagatesContextFailure(t *testing.T) {
	withFake(t, nil, ErrUnsupported, false)
	if err := Available(PolicyOwner); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Available error = %v, want ErrUnsupported", err)
	}
}

// ---------------------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------------------

func TestEvaluateEmptyReasonNeverReachesTheFramework(t *testing.T) {
	called := false
	origNew := newContext
	t.Cleanup(func() { newContext = origNew })
	newContext = func(options) (laContext, error) { called = true; return &fakeContext{}, nil }

	if err := Evaluate(context.Background(), PolicyOwner, ""); !errors.Is(err, ErrEmptyReason) {
		t.Fatalf("Evaluate(\"\") = %v, want ErrEmptyReason", err)
	}
	// The guard exists because an empty reason raises NSInvalidArgumentException,
	// which terminates the process. Reaching the backend at all defeats it.
	if called {
		t.Fatal("an empty reason must be rejected before any LAContext is built")
	}
}

func TestEvaluateSuccess(t *testing.T) {
	fc := &fakeContext{replyOK: true}
	withFake(t, fc, nil, false)

	if err := Evaluate(context.Background(), PolicyOwner, "unlock this document"); err != nil {
		t.Fatalf("Evaluate = %v, want nil", err)
	}
	if fc.lastReason != "unlock this document" || fc.lastPolicy != int(PolicyOwner) {
		t.Fatalf("backend got (policy %d, reason %q)", fc.lastPolicy, fc.lastReason)
	}
	if fc.released != 1 || fc.invalidated != 0 {
		t.Fatalf("released=%d invalidated=%d, want 1 and 0", fc.released, fc.invalidated)
	}
}

// TestEvaluateDistinguishesEveryOutcome is the reason this API returns an error
// and not a bool: each of these means something different to a caller.
func TestEvaluateDistinguishesEveryOutcome(t *testing.T) {
	for _, tc := range []struct {
		code int
		want error
	}{
		{codeAuthenticationFailed, ErrAuthenticationFailed},
		{codeUserCancel, ErrUserCancel},
		{codeUserFallback, ErrUserFallback},
		{codeSystemCancel, ErrSystemCancel},
		{codePasscodeNotSet, ErrPasscodeNotSet},
		{codeBiometryNotAvailable, ErrBiometryNotAvailable},
		{codeBiometryNotEnrolled, ErrBiometryNotEnrolled},
		{codeBiometryLockout, ErrBiometryLockout},
		{codeAppCancel, ErrAppCancel},
		{codeInvalidContext, ErrInvalidContext},
		{codeCompanionNotAvailable, ErrCompanionNotAvailable},
		{codeBiometryNotPaired, ErrBiometryNotPaired},
		{codeBiometryDisconnected, ErrBiometryDisconnected},
		{codeInvalidDimensions, ErrInvalidDimensions},
		{codeNotInteractive, ErrNotInteractive},
	} {
		fc := &fakeContext{replyCode: tc.code, replyMsg: "system says so"}
		withFake(t, fc, nil, false)
		err := Evaluate(context.Background(), PolicyOwner, "unlock")
		if !errors.Is(err, tc.want) {
			t.Errorf("LAError %d mapped to %v, want %v", tc.code, err, tc.want)
		}
		var e *Error
		if !errors.As(err, &e) || e.Op != "evaluate" || e.Code != tc.code {
			t.Errorf("LAError %d: *Error = %+v", tc.code, e)
		}
	}
}

func TestEvaluateUnknownCodeKeepsTheRawTruth(t *testing.T) {
	fc := &fakeContext{replyCode: -424242, replyMsg: "something new"}
	withFake(t, fc, nil, false)

	err := Evaluate(context.Background(), PolicyOwner, "unlock")
	var e *Error
	if !errors.As(err, &e) || e.Code != -424242 {
		t.Fatalf("Evaluate error = %v, want *Error carrying the raw code", err)
	}
	// Inventing a category for a code we do not know would be a guess. It
	// unwraps to nothing, and the message keeps the system's own words.
	for _, sentinel := range sentinels {
		if errors.Is(err, sentinel) {
			t.Fatalf("unknown code must not unwrap to %v", sentinel)
		}
	}
	if !strings.Contains(e.Error(), "something new") {
		t.Fatalf("Error() = %q, want the system message in it", e.Error())
	}
}

func TestEvaluatePropagatesContextFailure(t *testing.T) {
	withFake(t, nil, ErrUnsupported, false)
	if err := Evaluate(context.Background(), PolicyOwner, "unlock"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Evaluate error = %v, want ErrUnsupported", err)
	}
}

func TestEvaluateWithAnAlreadyCancelledContextShowsNoPrompt(t *testing.T) {
	prompted := false
	fc := &fakeContext{evaluate: func(int, string, func(bool, int, string)) { prompted = true }}
	withFake(t, fc, nil, false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Evaluate(ctx, PolicyOwner, "unlock"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Evaluate error = %v, want context.Canceled", err)
	}
	if prompted {
		t.Fatal("a dead context must not put a dialog on screen")
	}
	if fc.released != 1 {
		t.Fatalf("Release called %d times, want 1", fc.released)
	}
}

func TestEvaluateCancellationInvalidatesTheContext(t *testing.T) {
	// An evaluation that never replies — a dialog sitting on screen with
	// nobody at the keyboard.
	fc := &fakeContext{evaluate: func(int, string, func(bool, int, string)) {}}
	withFake(t, fc, nil, false)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()

	err := Evaluate(ctx, PolicyOwner, "unlock")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Evaluate error = %v, want context.Canceled", err)
	}
	// Invalidate is what actually dismisses the dialog; returning without it
	// would leave the prompt up.
	if fc.invalidated != 1 {
		t.Fatalf("Invalidate called %d times, want 1", fc.invalidated)
	}
	if fc.released != 1 {
		t.Fatalf("Release called %d times, want 1", fc.released)
	}
}

func TestEvaluateLateReplyDoesNotBlock(t *testing.T) {
	// After cancellation the framework still calls the reply, with
	// LAErrorAppCancel, on its own queue. Nobody is receiving by then, so the
	// channel must be buffered or that queue would be stuck forever.
	var late func(bool, int, string)
	fc := &fakeContext{evaluate: func(_ int, _ string, reply func(bool, int, string)) { late = reply }}
	withFake(t, fc, nil, false)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	if err := Evaluate(ctx, PolicyOwner, "unlock"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Evaluate error = %v, want context.Canceled", err)
	}

	done := make(chan struct{})
	go func() { late(false, codeAppCancel, "cancelled"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the late reply blocked: the done channel is not buffered")
	}
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

func TestOptionsReachTheBackend(t *testing.T) {
	fc := &fakeContext{replyOK: true}
	got := withFake(t, fc, nil, false)

	if err := Evaluate(context.Background(), PolicyBiometrics, "unlock",
		WithFallbackTitle("Use your password"),
		WithCancelTitle("Not now"),
		WithoutInteraction(),
	); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want := options{
		fallbackTitle: "Use your password", setFallbackTitle: true,
		cancelTitle: "Not now", setCancelTitle: true,
		nonInteractive: true,
	}
	if *got != want {
		t.Fatalf("options = %+v, want %+v", *got, want)
	}
}

func TestEmptyFallbackTitleIsAnInstruction(t *testing.T) {
	// "" hides the fallback button, which is different from not setting the
	// option at all — so the flag, not the string, has to carry the intent.
	fc := &fakeContext{replyOK: true}
	got := withFake(t, fc, nil, false)

	if err := Evaluate(context.Background(), PolicyBiometrics, "unlock", WithFallbackTitle("")); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !got.setFallbackTitle || got.fallbackTitle != "" {
		t.Fatalf("options = %+v, want setFallbackTitle with an empty title", *got)
	}
}

func TestNoOptionsSetsNothing(t *testing.T) {
	fc := &fakeContext{replyOK: true}
	got := withFake(t, fc, nil, false)
	if err := Evaluate(context.Background(), PolicyOwner, "unlock"); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if (*got != options{}) {
		t.Fatalf("options = %+v, want the zero value", *got)
	}
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

func TestErrorString(t *testing.T) {
	e := &Error{Op: "evaluate", Code: codeUserCancel, Message: "Canceled by user."}
	want := "localauthentication: evaluate: LAError -2: Canceled by user."
	if got := e.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestErrorStringWithoutAMessage(t *testing.T) {
	e := &Error{Op: "available", Code: 0}
	if got := e.Error(); got != "localauthentication: available: LAError 0: no message" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestErrorStringNamesAppbundleWhenUnbundled(t *testing.T) {
	e := &Error{Op: "evaluate", Code: codeBiometryNotAvailable, Message: "nope", Unbundled: true}
	got := e.Error()
	if !strings.Contains(got, "appbundle") || !strings.Contains(got, "not an .app bundle") {
		t.Fatalf("Error() = %q, want the bundle cause spelled out", got)
	}
	if !errors.Is(e, ErrNotBundled) {
		t.Fatal("an unbundled error must unwrap to ErrNotBundled")
	}
	// And it must still carry its own cause.
	if !errors.Is(e, ErrBiometryNotAvailable) {
		t.Fatal("the bundle note must not replace the real cause")
	}
}

func TestUnbundledNoteIsAttachedOnlyToSetupFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		want bool
	}{
		// The dialog was shown and answered: identity plainly worked, so the
		// note would be noise.
		{"user cancelled", codeUserCancel, false},
		{"user asked for the password", codeUserFallback, false},
		{"wrong finger", codeAuthenticationFailed, false},
		{"system interrupted", codeSystemCancel, false},
		// Nothing was ever shown: a missing bundle is a real candidate.
		{"biometry unavailable", codeBiometryNotAvailable, true},
		{"not interactive", codeNotInteractive, true},
		{"no NSError at all", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFake(t, &fakeContext{replyCode: tc.code}, nil, true)
			err := Evaluate(context.Background(), PolicyOwner, "unlock")
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("error = %v, want *Error", err)
			}
			if e.Unbundled != tc.want {
				t.Fatalf("Unbundled = %v, want %v", e.Unbundled, tc.want)
			}
			if errors.Is(err, ErrNotBundled) != tc.want {
				t.Fatalf("errors.Is(ErrNotBundled) = %v, want %v", errors.Is(err, ErrNotBundled), tc.want)
			}
		})
	}
}

func TestBundledProcessNeverGetsTheNote(t *testing.T) {
	withFake(t, &fakeContext{replyCode: codeBiometryNotAvailable}, nil, false)
	err := Evaluate(context.Background(), PolicyOwner, "unlock")
	if errors.Is(err, ErrNotBundled) {
		t.Fatalf("a bundled process must not be blamed for a missing bundle: %v", err)
	}
}

func TestUnwrapOfAPlainError(t *testing.T) {
	if got := (&Error{Code: 0}).Unwrap(); got != nil {
		t.Fatalf("Unwrap = %v, want nil for an unknown, bundled failure", got)
	}
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

func TestPolicyString(t *testing.T) {
	for _, tc := range []struct {
		p    Policy
		want string
	}{
		{PolicyBiometrics, "biometrics"},
		{PolicyOwner, "biometrics-or-password"},
		{Policy(7), "LAPolicy(7)"},
	} {
		if got := tc.p.String(); got != tc.want {
			t.Errorf("Policy(%d).String() = %q, want %q", tc.p, got, tc.want)
		}
	}
}

func TestBiometryTypeString(t *testing.T) {
	for _, tc := range []struct {
		b    BiometryType
		want string
	}{
		{BiometryNone, "none"},
		{BiometryTouchID, "Touch ID"},
		{BiometryFaceID, "Face ID"},
		{BiometryOpticID, "Optic ID"},
		{BiometryType(9), "LABiometryType(9)"},
	} {
		if got := tc.b.String(); got != tc.want {
			t.Errorf("BiometryType(%d).String() = %q, want %q", tc.b, got, tc.want)
		}
	}
}

// TestPolicyValuesMatchTheSDK pins the two constants to LAPublicDefines.h.
// They are 1 and 2 — NOT 0 and 1, which is the value pair people misremember,
// and getting it wrong would silently evaluate the wrong policy (0 is not a
// policy at all; 1 is biometrics-only where 2 was meant).
func TestPolicyValuesMatchTheSDK(t *testing.T) {
	if PolicyBiometrics != 1 || PolicyOwner != 2 {
		t.Fatalf("policies = (%d, %d), want (1, 2) per LAPublicDefines.h", PolicyBiometrics, PolicyOwner)
	}
	if BiometryNone != 0 || BiometryTouchID != 1 || BiometryFaceID != 2 || BiometryOpticID != 4 {
		t.Fatal("LABiometryType values drifted from LAPublicDefines.h")
	}
}

// ---------------------------------------------------------------------------
// The policy guard
// ---------------------------------------------------------------------------

// TestUnknownPolicyNeverReachesTheBackend guards a crash, not a style rule.
// -[LAContext canEvaluatePolicy:error:] raises NSInvalidArgumentException for a
// policy it does not know, and that exception aborts the process — it does not
// become a Go panic and cannot be recovered. Reaching the backend at all is the
// defect.
func TestUnknownPolicyNeverReachesTheBackend(t *testing.T) {
	called := false
	origNew := newContext
	t.Cleanup(func() { newContext = origNew })
	newContext = func(options) (laContext, error) { called = true; return &fakeContext{}, nil }

	for _, p := range []Policy{0, 3, 4, 5, 9999, -1} {
		if err := Available(p); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("Available(%d) = %v, want ErrInvalidPolicy", p, err)
		}
		if err := Evaluate(context.Background(), p, "unlock"); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("Evaluate(%d) = %v, want ErrInvalidPolicy", p, err)
		}
	}
	if called {
		t.Fatal("an unknown policy must be rejected before any LAContext is built")
	}
	// The rejected value is in the message, because "unknown policy" alone
	// leaves the caller hunting for which constant they got wrong.
	if err := Available(Policy(42)); !strings.Contains(err.Error(), "42") {
		t.Fatalf("error = %q, want the rejected policy value in it", err)
	}
}

// TestKnownPoliciesAreAccepted is the other arm: the guard must not reject the
// two policies that are the whole point of the package.
func TestKnownPoliciesAreAccepted(t *testing.T) {
	withFake(t, &fakeContext{canOK: true, replyOK: true}, nil, false)
	for _, p := range []Policy{PolicyBiometrics, PolicyOwner} {
		if err := Available(p); err != nil {
			t.Errorf("Available(%v) = %v, want nil", p, err)
		}
		if err := Evaluate(context.Background(), p, "unlock"); err != nil {
			t.Errorf("Evaluate(%v) = %v, want nil", p, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

// TestGateSkipsWhenUnavailable: the convenience returns nil WITHOUT prompting
// when the policy cannot be evaluated, so a person with no biometrics/passcode is
// not locked out.
func TestGateSkipsWhenUnavailable(t *testing.T) {
	fc := &fakeContext{canOK: false, canCode: 1, canMessage: "no biometry"}
	withFake(t, fc, nil, false)
	if err := Gate(context.Background(), PolicyOwner, "unlock the vault"); err != nil {
		t.Fatalf("Gate must return nil when the policy is unavailable, got %v", err)
	}
	if fc.lastReason != "" {
		t.Fatal("Gate prompted despite the policy being unavailable")
	}
}

// TestGateEvaluatesWhenAvailable: when the policy can be evaluated, Gate prompts
// and returns nil on success.
func TestGateEvaluatesWhenAvailable(t *testing.T) {
	fc := &fakeContext{canOK: true, replyOK: true}
	withFake(t, fc, nil, false)
	if err := Gate(context.Background(), PolicyOwner, "unlock the vault"); err != nil {
		t.Fatalf("Gate should return nil on a successful evaluation, got %v", err)
	}
	if fc.lastReason != "unlock the vault" {
		t.Fatalf("Gate did not evaluate with the reason, lastReason=%q", fc.lastReason)
	}
}

// TestGatePropagatesEvaluationFailure: an available policy that the person fails
// or cancels surfaces the error.
func TestGatePropagatesEvaluationFailure(t *testing.T) {
	fc := &fakeContext{canOK: true, replyOK: false, replyCode: -128, replyMsg: "cancelled"}
	withFake(t, fc, nil, false)
	if err := Gate(context.Background(), PolicyOwner, "unlock the vault"); err == nil {
		t.Fatal("Gate must return the error when an available policy is failed/cancelled")
	}
}
