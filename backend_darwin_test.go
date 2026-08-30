// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package localauthentication

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-macos/objc"
)

// These tests run against the REAL LocalAuthentication framework — real class,
// real messages, a real Objective-C block — and not one of them can raise a
// Touch ID prompt.
//
// Two independent guarantees keep it that way, and both come from Apple's own
// headers rather than from hope:
//
//   - An INVALIDATED context "can not be used for policy evaluation and an
//     attempt to do so will fail with LAErrorInvalidContext" (LAContext.h).
//     There is nothing left to show a dialog with. This is the belt.
//   - interactionNotAllowed makes an evaluation "fail with LAErrorNotInteractive
//     instead of displaying the authentication UI" (LAContext.h). This is the
//     braces, and it is also the option under test.
//
// The one test that genuinely does prompt lives in live_darwin_test.go and is
// skipped unless a person sets an environment variable, because a test suite
// that puts a fingerprint sheet in front of whoever ran `go test` is a test
// suite people learn to stop running.

// evaluateTimeout bounds every wait on a reply block. Apple documents that
// invalidation and non-interactive refusal both produce a reply; if one ever
// does not, this fails the test instead of hanging CI forever.
const evaluateTimeout = 30 * time.Second

// waitForReply runs one real evaluation and returns what the reply block said.
func waitForReply(t *testing.T, c laContext, policy Policy, reason string) (bool, int, string) {
	t.Helper()
	type result struct {
		ok      bool
		code    int
		message string
	}
	done := make(chan result, 1)
	c.Evaluate(int(policy), reason, func(ok bool, code int, message string) {
		done <- result{ok, code, message}
	})
	select {
	case r := <-done:
		return r.ok, r.code, r.message
	case <-time.After(evaluateTimeout):
		t.Fatal("the reply block never fired: the block, or its retain, is wrong")
		return false, 0, ""
	}
}

// knownCode reports whether code is an LAError this package has a name for.
// A machine-dependent test can then assert something real — "the framework
// answered with an error we recognise" — without pinning the answer to the
// hardware the test happens to run on.
func knownCode(code int) bool {
	_, ok := sentinels[code]
	return ok
}

// ---------------------------------------------------------------------------
// Plumbing: the framework, the class, the object.
// ---------------------------------------------------------------------------

// TestFrameworkAndClassResolve is the check that catches a renamed framework
// or a class the runtime does not know, which would otherwise show up as every
// call quietly answering "unavailable".
func TestFrameworkAndClassResolve(t *testing.T) {
	if err := load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if laClass() == 0 {
		t.Fatal("the LAContext class is not registered after loading the framework")
	}
	for name, sel := range map[string]objc.SEL{
		"canEvaluatePolicy:error:":              selCanEvaluate,
		"evaluatePolicy:localizedReason:reply:": selEvaluate,
		"biometryType":                          selBiometryType,
		"invalidate":                            selInvalidate,
		"setInteractionNotAllowed:":             selSetNoInteraction,
		"setLocalizedFallbackTitle:":            selSetFallbackTitle,
		"setLocalizedCancelTitle:":              selSetCancelTitle,
	} {
		if sel == 0 {
			t.Errorf("selector %s did not resolve", name)
		}
	}
}

// TestNewContextConfiguresEveryOption drives all three option branches against
// the real class. None of the setters shows anything; they only prime a dialog
// that this test never asks for.
func TestNewContextConfiguresEveryOption(t *testing.T) {
	c, err := platformNewContext(options{
		fallbackTitle: "Use your password", setFallbackTitle: true,
		cancelTitle: "Not now", setCancelTitle: true,
		nonInteractive: true,
	})
	if err != nil {
		t.Fatalf("platformNewContext: %v", err)
	}
	defer c.Release()
	if c.(*darwinContext).id == 0 {
		t.Fatal("context id is nil")
	}
}

// TestNewContextWithNoOptions covers the other arm of each option branch.
func TestNewContextWithNoOptions(t *testing.T) {
	c, err := platformNewContext(options{})
	if err != nil {
		t.Fatalf("platformNewContext: %v", err)
	}
	c.Release()
}

// ---------------------------------------------------------------------------
// canEvaluatePolicy: and biometryType — neither shows any UI.
// ---------------------------------------------------------------------------

// TestCanEvaluateAnswersForBothPolicies calls the real preflight. What it
// answers depends on the machine — a CI runner has no Touch ID — so the
// assertion is on the SHAPE of the answer, which is machine-independent: either
// it can, or it says why not in a code we recognise.
func TestCanEvaluateAnswersForBothPolicies(t *testing.T) {
	for _, p := range []Policy{PolicyBiometrics, PolicyOwner} {
		c, err := platformNewContext(options{})
		if err != nil {
			t.Fatalf("platformNewContext: %v", err)
		}
		ok, code, message := c.CanEvaluate(int(p))
		c.Release()
		t.Logf("canEvaluatePolicy(%v) = %v, code %d, %q", p, ok, code, message)
		if ok {
			if code != 0 || message != "" {
				t.Errorf("%v: success carried an error (%d, %q)", p, code, message)
			}
			continue
		}
		if !knownCode(code) {
			t.Errorf("%v: refused with unknown LAError %d (%q)", p, code, message)
		}
	}
}

// TestUnknownPolicyIsRejectedBeforeTheFramework is the test that found the
// worst trap in this API, and it found it by crashing the whole test binary.
//
// -[LAContext canEvaluatePolicy:error:] does NOT return an error for a policy
// it does not recognise. It raises:
//
//	*** Terminating app due to uncaught exception 'NSInvalidArgumentException',
//	    reason: 'Error Domain=com.apple.LocalAuthentication Code=-1001
//	    "Unknown policy: '9999'"'
//
// An Objective-C exception unwinding through a purego frame does not become a
// Go panic; the process aborts. So the guard is in the portable layer, and this
// test asserts that the framework is never reached — it deliberately does NOT
// call CanEvaluate with a bogus policy, because doing so is what killed the
// binary in the first place.
func TestUnknownPolicyIsRejectedBeforeTheFramework(t *testing.T) {
	for _, p := range []Policy{0, 3, 9999, -1} {
		if err := Available(p); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("Available(%d) = %v, want ErrInvalidPolicy", p, err)
		}
		if err := Evaluate(t.Context(), p, "run this package's tests"); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("Evaluate(%d) = %v, want ErrInvalidPolicy", p, err)
		}
	}
}

// TestBiometryTypeIsOneOfTheDeclaredValues reads the property through the whole
// public path, which is also what proves the CanEvaluate-first ordering does
// not crash. The VALUE is hardware; only its membership is asserted.
func TestBiometryTypeIsOneOfTheDeclaredValues(t *testing.T) {
	got, err := Biometry()
	if err != nil {
		t.Fatalf("Biometry: %v", err)
	}
	switch got {
	case BiometryNone, BiometryTouchID, BiometryFaceID, BiometryOpticID:
		t.Logf("this machine reports %v", got)
	default:
		t.Fatalf("biometryType = %d, which LABiometryType does not define", got)
	}
}

// ---------------------------------------------------------------------------
// The block. This is the part that had to be proven rather than assumed.
// ---------------------------------------------------------------------------

// TestEvaluateOnAnInvalidatedContextRunsTheRealBlock is the safe end-to-end
// proof: a real -evaluatePolicy:localizedReason:reply: with a real
// objc.NewBlock, on a context that has been invalidated first.
//
// It cannot prompt. Invalidation tears the context down, so there is nothing
// left that could present a dialog — and the reply still fires, with
// LAErrorInvalidContext, which is exactly the round trip that had to be shown
// to work: Go closure -> Objective-C block -> framework -> back onto a thread
// Go did not create -> channel send.
func TestEvaluateOnAnInvalidatedContextRunsTheRealBlock(t *testing.T) {
	c, err := platformNewContext(options{})
	if err != nil {
		t.Fatalf("platformNewContext: %v", err)
	}
	defer c.Release()
	c.Invalidate()

	ok, code, message := waitForReply(t, c, PolicyOwner, "run this package's tests")
	if ok {
		t.Fatal("an invalidated context reported success")
	}
	if code != codeInvalidContext {
		t.Fatalf("LAError %d (%q), want %d (invalid context)", code, message, codeInvalidContext)
	}
	if message == "" {
		t.Error("the NSError carried no localizedDescription")
	}
	t.Logf("invalidated context replied: LAError %d %q", code, message)
}

// TestEvaluateWithoutInteractionNeverPrompts drives the whole public path —
// Evaluate, options, block, error mapping — with interactionNotAllowed set,
// which Apple documents as failing INSTEAD of showing UI.
//
// The expected outcome is [ErrNotInteractive] on a machine where the policy
// could otherwise be evaluated, and a setup error (no biometry, no passcode)
// on one where it could not; a CI runner gives the second. Both are errors, and
// nil is the only unacceptable answer: nil would mean something authenticated
// somebody, which is precisely what must never happen unattended.
func TestEvaluateWithoutInteractionNeverPrompts(t *testing.T) {
	err := Evaluate(t.Context(), PolicyBiometrics, "run this package's tests", WithoutInteraction())
	if err == nil {
		t.Fatal("a non-interactive evaluation SUCCEEDED — it must never authenticate anyone")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error = %v, want *Error", err)
	}
	if !knownCode(e.Code) {
		t.Fatalf("unknown LAError %d: %q", e.Code, e.Message)
	}
	t.Logf("non-interactive evaluation refused: %v", err)
}

// ---------------------------------------------------------------------------
// NSError reading.
// ---------------------------------------------------------------------------

func TestErrorInfoOfNil(t *testing.T) {
	// The out-parameter is only guaranteed to be set on failure. A nil one
	// dereferenced would be a crash, not an error message.
	if code, message := errorInfo(0); code != 0 || message != "" {
		t.Fatalf("errorInfo(nil) = (%d, %q), want (0, \"\")", code, message)
	}
}

func TestErrorInfoReadsARealNSError(t *testing.T) {
	if err := load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	nsErr := objc.ClassID("NSError").Send(objc.Sel("errorWithDomain:code:userInfo:"),
		objc.NSString("com.apple.LocalAuthentication"), codeBiometryLockout, objc.ID(0))
	if nsErr == 0 {
		t.Fatal("+[NSError errorWithDomain:code:userInfo:] returned nil")
	}
	code, message := errorInfo(nsErr)
	if code != codeBiometryLockout {
		t.Fatalf("code = %d, want %d", code, codeBiometryLockout)
	}
	if message == "" {
		t.Fatal("localizedDescription was empty")
	}
}

// ---------------------------------------------------------------------------
// The failure branches. None of these can be provoked on a Mac where the
// framework works, which is the whole reason the seams exist.
// ---------------------------------------------------------------------------

// withLoadSeam replaces the framework loader and resets the sync.Once that
// guards it, so a load failure can be driven on a machine where loading
// succeeds. Both are restored afterwards, so the tests that follow see the
// real framework again.
func withLoadSeam(t *testing.T, fn func() error) {
	t.Helper()
	origLoad, origOnce, origErr := laLoad, loadOnce, loadErr
	t.Cleanup(func() { laLoad, loadOnce, loadErr = origLoad, origOnce, origErr })
	laLoad, loadOnce, loadErr = fn, new(sync.Once), nil
}

func TestNewContextWhenTheFrameworkWillNotLoad(t *testing.T) {
	withLoadSeam(t, func() error { return errors.New("dlopen refused") })

	_, err := platformNewContext(options{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "dlopen refused") {
		t.Fatalf("error = %q, want the underlying dlopen failure kept", err)
	}
	// And it is remembered rather than retried on every call.
	if _, err2 := platformNewContext(options{}); err2 == nil || err2.Error() != err.Error() {
		t.Fatalf("second call = %v, want the same remembered failure", err2)
	}
}

func TestUnbundledIsFalseWhenTheFrameworkWillNotLoad(t *testing.T) {
	withLoadSeam(t, func() error { return errors.New("dlopen refused") })
	// With no framework there is no NSBundle to ask, so blaming the caller's
	// packaging would be an invention.
	if platformUnbundled() {
		t.Fatal("platformUnbundled must not claim a missing bundle it could not check")
	}
}

func TestNewContextWhenTheClassIsMissing(t *testing.T) {
	orig := laClass
	t.Cleanup(func() { laClass = orig })
	laClass = func() objc.ID { return 0 }

	_, err := platformNewContext(options{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	// A message to a nil class returns zero in silence. The error has to name
	// the step, or there is nothing anywhere to read.
	if !strings.Contains(err.Error(), "LAContext class") {
		t.Fatalf("error = %q, want the missing class named", err)
	}
}

func TestNewContextWhenInitReturnsNil(t *testing.T) {
	orig := laAlloc
	t.Cleanup(func() { laAlloc = orig })
	laAlloc = func(objc.ID) objc.ID { return 0 }

	_, err := platformNewContext(options{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "init") {
		t.Fatalf("error = %q, want -[LAContext init] named", err)
	}
}

func TestBundleIdentifierWithoutAMainBundle(t *testing.T) {
	orig := mainBundle
	t.Cleanup(func() { mainBundle = orig })
	mainBundle = func() objc.ID { return 0 }

	if got := bundleIdentifier(); got != "" {
		t.Fatalf("bundleIdentifier = %q, want \"\"", got)
	}
	if !platformUnbundled() {
		t.Fatal("platformUnbundled = false with no main bundle")
	}
}

func TestBundleIdentifierOfAPretendBundle(t *testing.T) {
	if err := load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	// Any object that answers -bundleIdentifier will do; a real .app cannot be
	// conjured inside a test process. NSProcessInfo does not, so stand in with
	// a real NSBundle built from a path that exists.
	orig := mainBundle
	t.Cleanup(func() { mainBundle = orig })
	bundle := objc.ClassID("NSBundle").Send(objc.Sel("bundleWithPath:"),
		objc.NSString("/System/Library/CoreServices/Finder.app"))
	if bundle == 0 {
		t.Skip("Finder.app is not present on this system")
	}
	mainBundle = func() objc.ID { return bundle }

	if got := bundleIdentifier(); got != "com.apple.finder" {
		t.Fatalf("bundleIdentifier = %q, want com.apple.finder", got)
	}
	if platformUnbundled() {
		t.Fatal("platformUnbundled = true for a process with a bundle identifier")
	}
}

// TestThisTestBinaryIsUnbundled records the fact the appbundle hint exists for:
// a bare `go test` binary has no bundle identifier, which is exactly the
// situation a consumer hits when they run their program with `go run` and
// wonder why authentication will not work.
func TestThisTestBinaryIsUnbundled(t *testing.T) {
	if !platformUnbundled() {
		t.Fatalf("a `go test` binary reported a bundle identifier %q — unexpected, "+
			"but not a defect in this package", bundleIdentifier())
	}
}
