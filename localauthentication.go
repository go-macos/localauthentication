// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package localauthentication asks macOS to authenticate the person at the
// keyboard — Touch ID, or the login password — from pure Go with
// CGO_ENABLED=0.
//
// It binds LAContext from the LocalAuthentication framework through
// github.com/go-macos/objc (Objective-C message sends over
// github.com/ebitengine/purego), so it links with no cgo.
//
// # What this is, and what it is not
//
// A biometric check is NOT something a program implements. The fingerprint
// never leaves the Secure Enclave; nothing in this process — or in the kernel —
// ever sees it. What LocalAuthentication returns is an ATTESTATION: the system
// says that the device owner was present and identified themselves. This
// package is a way to ask for that attestation and to report faithfully what
// came back. It cannot verify anything itself, and it can be lied to by
// anything that can patch this process, so it is a gate on convenience, not a
// cryptographic control. Data that must actually stay secret is protected by
// storing the key in the Keychain behind a SecAccessControl — see "Should this
// package know about the Keychain?" below.
//
// # Using it
//
//	// Is there any biometric hardware, and of what kind?
//	kind, err := localauthentication.Biometry()   // TouchID, FaceID, OpticID, None
//
//	// Could this policy be evaluated right now? (No prompt; no side effect.)
//	err := localauthentication.Available(localauthentication.PolicyBiometrics)
//
//	// Ask. THIS PROMPTS. It blocks until the person answers.
//	err := localauthentication.Evaluate(ctx,
//		localauthentication.PolicyOwner, "unlock this document")
//	switch {
//	case err == nil:                                        // authenticated
//	case errors.Is(err, localauthentication.ErrUserCancel):  // they said no
//	case errors.Is(err, localauthentication.ErrBiometryLockout): // too many tries
//	default:                                                // see the table in the README
//	}
//
// # A bool would be a lie
//
// [Evaluate] returns an error, not a boolean, because "it did not succeed"
// covers a dozen situations a caller must treat differently. The person
// pressing Cancel ([ErrUserCancel]) is a decision to respect; the person
// pressing "Use Password…" ([ErrUserFallback]) is a request to offer another
// route; a finger that did not match ([ErrAuthenticationFailed]) invites
// another try; a Mac with no Touch ID at all ([ErrBiometryNotAvailable]) means
// never offering the option again this session; and five failures in a row
// ([ErrBiometryLockout]) means the sensor is now locked until the account
// password is entered, so retrying is pointless and only annoys. Collapsing
// all of that into false would make each of those the same, and every caller
// would then guess.
//
// Every failure is a [*Error] carrying the raw LAError code and the system's
// own localised message, and it unwraps to one of the sentinels above, so
// errors.Is answers the question a caller actually has while errors.As keeps
// the detail for a log.
//
// # It needs an .app bundle
//
// LocalAuthentication identifies the asking program by its bundle: the prompt
// reads "«AppName» is trying to <your reason>". A bare executable built by
// go build has no bundle and no bundle identifier, and evaluation from one is
// unreliable — it may be refused outright, and where it is not, the dialog has
// no name to show. Build a real bundle with
// github.com/go-macos/appbundle and run from inside it. When a failure arrives
// and this process is NOT bundled, the [*Error] says so (its Unbundled field is
// set, it unwraps to [ErrNotBundled], and Error() names appbundle), so the
// cause is stated rather than guessed at.
//
// This package cannot fix that for you: a bundle identity is decided when the
// program is packaged, not when it runs.
//
// # The reply is a block, and this API is synchronous
//
// -[LAContext evaluatePolicy:localizedReason:reply:] is asynchronous and takes
// an Objective-C BLOCK, not a function pointer. That IS practicable here:
// github.com/go-macos/objc exposes NewBlock, and the darwin backend passes a
// real block whose Go closure hands the result back over a channel. Nothing is
// faked and nothing is polled.
//
// [Evaluate] then BLOCKS until the reply arrives, because a synchronous call is
// what every caller of this actually wants — the answer decides what happens
// next. Apple documents that the reply block runs "on a private queue internal
// to the framework", so no run loop of yours has to be turning for it to fire.
//
//	⚠ Do not call Evaluate from the main thread of a GUI program while that
//	thread is blocked. AppKit needs the main thread; a program that blocks it
//	waiting for an answer can deny the system the thread it needs to show the
//	sheet. Call it from a goroutine and post the result back
//	(objc.DispatchMain).
//
// Pass a context: cancelling it invalidates the LAContext, which Apple
// documents as terminating any evaluation in progress. [Evaluate] then returns
// ctx.Err() — the reply still fires afterwards (with LAErrorAppCancel) and the
// backend releases the block and the context there, so nothing leaks.
//
// # Should this package know about the Keychain?
//
// Deliberately, it does not. github.com/go-macos/keychain can already store an
// item behind a SecAccessControl with kSecAccessControlUserPresence, and
// READING such an item prompts for Touch ID by itself — the Keychain asks
// LocalAuthentication on the caller's behalf, and nothing in this package is
// involved. That is the stronger arrangement, because the secret is genuinely
// unreadable until the attestation is made, instead of being readable by
// anything that skips a check.
//
// This package is for the other case: gating an action that has no secret
// behind it — reopening a document that is already decrypted in memory,
// revealing a field, confirming a destructive step.
//
// There IS one real seam between the two, and it is not implemented here:
// LAContext can be handed to a Keychain query as kSecUseAuthenticationContext,
// so one successful evaluation authorises a subsequent read without a second
// prompt. Wiring that up means exposing a live LAContext across a package
// boundary and agreeing on its lifetime; it belongs in whichever package owns
// the query, and it should be designed rather than fallen into. Until then the
// two packages stay independent, and a caller that wants a gate AND a secret
// uses keychain's WithAccessControl(UserPresence) — one prompt, enforced by the
// Keychain.
package localauthentication

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// Policy is an LAPolicy: what the system should accept as proof.
type Policy int

// The two policies that make sense on macOS. The values are LAPolicy's, read
// from LAPublicDefines.h in the macOS SDK.
//
// (Note for anyone checking against a half-remembered constant: these are 1 and
// 2, not 0 and 1. There is no LAPolicy 0.)
const (
	// PolicyBiometrics is LAPolicyDeviceOwnerAuthenticationWithBiometrics:
	// Touch ID and nothing else. If biometry is unavailable, unenrolled or
	// locked out, evaluation FAILS rather than falling back — which is the
	// point of asking for it. The dialog's "Use Password…" button ends the
	// evaluation with [ErrUserFallback], leaving the caller to decide what to
	// offer instead.
	PolicyBiometrics Policy = 1
	// PolicyOwner is LAPolicyDeviceOwnerAuthentication: Touch ID OR the
	// account password. If biometry cannot be used the password is asked for
	// straight away, and "Use Password…" switches the same dialog over rather
	// than ending it — so [ErrUserFallback] does not arise. This is the right
	// choice for unlocking something the owner must always be able to reach.
	PolicyOwner Policy = 2
)

// String names the policy.
func (p Policy) String() string {
	switch p {
	case PolicyBiometrics:
		return "biometrics"
	case PolicyOwner:
		return "biometrics-or-password"
	default:
		return "LAPolicy(" + strconv.Itoa(int(p)) + ")"
	}
}

// valid reports whether p is a policy this package will pass to LAContext.
// It is a safety gate, not a style check: see [ErrInvalidPolicy] for what an
// unknown policy actually does.
func (p Policy) valid() bool { return p == PolicyBiometrics || p == PolicyOwner }

// BiometryType is an LABiometryType: which biometric sensor this Mac has, if
// any. The values are a bit set in LAPublicDefines.h, but Apple's own property
// reports exactly one of them.
type BiometryType int

// The biometry kinds LABiometryType defines.
const (
	// BiometryNone means there is no biometric sensor, or none this process
	// may use.
	BiometryNone BiometryType = 0
	// BiometryTouchID is a fingerprint sensor — the only kind a Mac has today.
	BiometryTouchID BiometryType = 1
	// BiometryFaceID exists in LABiometryType and is declared available on
	// macOS 10.15+, but no Mac ships it. Handle it; do not expect it.
	BiometryFaceID BiometryType = 2
	// BiometryOpticID is Apple Vision Pro's iris sensor. Declared on macOS 14+
	// for source compatibility; no Mac has one.
	BiometryOpticID BiometryType = 4
)

// String names the sensor.
func (b BiometryType) String() string {
	switch b {
	case BiometryNone:
		return "none"
	case BiometryTouchID:
		return "Touch ID"
	case BiometryFaceID:
		return "Face ID"
	case BiometryOpticID:
		return "Optic ID"
	default:
		return "LABiometryType(" + strconv.Itoa(int(b)) + ")"
	}
}

// Errors this package raises before it ever reaches the framework.
var (
	// ErrUnsupported is what every entry point answers away from macOS.
	// The exported surface exists on every platform so consumers
	// cross-compile.
	ErrUnsupported = errors.New("localauthentication: unsupported on this platform (macOS only)")
	// ErrUnavailable means the LocalAuthentication framework, the LAContext
	// class, or a context object could not be obtained. A message to a nil
	// object returns zero IN SILENCE, so every acquisition here is checked and
	// this is what a nil one is reported as.
	ErrUnavailable = errors.New("localauthentication: the LocalAuthentication framework is not available")
	// ErrEmptyReason is returned by [Evaluate] when reason is "". This is a
	// guard, not a preference: -[LAContext evaluatePolicy:localizedReason:reply:]
	// raises NSInvalidArgumentException for an empty reason, and an
	// Objective-C exception crossing a purego frame terminates the process —
	// there is no recover() for it.
	ErrEmptyReason = errors.New("localauthentication: a localized reason is required")
	// ErrInvalidPolicy is returned when the policy is not one this package
	// defines.
	//
	// This one was found the hard way, by a test. LAContext does NOT return an
	// error for a policy it does not know: -canEvaluatePolicy:error: RAISES
	// NSInvalidArgumentException ("Unknown policy: '9999'"), and an Objective-C
	// exception unwinding through a purego frame is not recoverable — the
	// process aborts, with an NSException backtrace and no Go panic to catch.
	// So the policy is checked here, before the framework is reached, exactly
	// as the empty reason is.
	ErrInvalidPolicy = errors.New("localauthentication: unknown policy")
	// ErrNotBundled reports that this process is not running from an .app
	// bundle, so LocalAuthentication has no application identity to show in
	// its prompt. A [*Error] unwraps to this in ADDITION to its own cause when
	// the failure is one a missing bundle could explain. Build a bundle with
	// github.com/go-macos/appbundle.
	ErrNotBundled = errors.New("localauthentication: this process is not an .app bundle (see github.com/go-macos/appbundle)")
)

// The LAError codes, as sentinels. Each is what a [*Error] unwraps to, so a
// caller writes errors.Is(err, ErrUserCancel) rather than comparing integers.
// The codes are LAError's, read from LAPublicDefines.h in the macOS SDK.
var (
	// ErrAuthenticationFailed (-1): the credential was wrong — a finger that
	// did not match, or a bad password. The person is present and trying;
	// offering another attempt is reasonable.
	ErrAuthenticationFailed = errors.New("localauthentication: authentication failed")
	// ErrUserCancel (-2): they pressed Cancel. A decision, not a fault. Do not
	// re-prompt.
	ErrUserCancel = errors.New("localauthentication: cancelled by the user")
	// ErrUserFallback (-3): they pressed "Use Password…" under
	// [PolicyBiometrics], which ENDS the evaluation. Offer your own route, or
	// re-evaluate under [PolicyOwner] so the system asks for the password
	// itself. It does not arise under PolicyOwner.
	ErrUserFallback = errors.New("localauthentication: the user asked to fall back to a password")
	// ErrSystemCancel (-4): the system interrupted the dialog — another app
	// came forward, the screen locked. Nobody decided anything; retrying when
	// the program is frontmost again is fine.
	ErrSystemCancel = errors.New("localauthentication: cancelled by the system")
	// ErrPasscodeNotSet (-5): the account has no password set, so
	// [PolicyOwner] has nothing to fall back to.
	ErrPasscodeNotSet = errors.New("localauthentication: no device passcode is set")
	// ErrBiometryNotAvailable (-6): this Mac has no usable biometric sensor,
	// or this process may not use it. Stop offering the option.
	ErrBiometryNotAvailable = errors.New("localauthentication: biometry is not available")
	// ErrBiometryNotEnrolled (-7): there is a sensor but no fingerprint is
	// enrolled. Worth telling the person, because they can fix it in System
	// Settings.
	ErrBiometryNotEnrolled = errors.New("localauthentication: biometry has no enrolled identity")
	// ErrBiometryLockout (-8): five failures in a row; the sensor is locked
	// until the account password is entered. Retrying [PolicyBiometrics] is
	// pointless — re-evaluate [PolicyOwner], which asks for the password and
	// unlocks the sensor as a side effect.
	ErrBiometryLockout = errors.New("localauthentication: biometry is locked out after too many failed attempts")
	// ErrAppCancel (-9): the program itself cancelled — this is what a
	// cancelled context produces, after [Evaluate] has already returned
	// ctx.Err().
	ErrAppCancel = errors.New("localauthentication: cancelled by the application")
	// ErrInvalidContext (-10): the LAContext was already invalidated. This
	// package builds a fresh one per call, so it should not occur.
	ErrInvalidContext = errors.New("localauthentication: the authentication context is invalid")
	// ErrCompanionNotAvailable (-11): no paired Apple Watch nearby. Only for
	// the companion policies, which this package does not expose.
	ErrCompanionNotAvailable = errors.New("localauthentication: no companion device is available")
	// ErrBiometryNotPaired (-12): biometry is provided by a removable
	// accessory (a Magic Keyboard with Touch ID) that has never been paired.
	ErrBiometryNotPaired = errors.New("localauthentication: the biometric accessory is not paired")
	// ErrBiometryDisconnected (-13): that accessory is paired but not
	// connected right now.
	ErrBiometryDisconnected = errors.New("localauthentication: the biometric accessory is disconnected")
	// ErrInvalidDimensions (-14): the embedded authentication view was given
	// invalid dimensions. Not reachable through this package.
	ErrInvalidDimensions = errors.New("localauthentication: invalid embedded UI dimensions")
	// ErrNotInteractive (-1004): UI was required but forbidden, because
	// [WithoutInteraction] was used. This is the outcome that lets the test
	// suite drive a real evaluation end to end without ever showing a prompt.
	ErrNotInteractive = errors.New("localauthentication: interaction is not allowed")
)

// LAError codes. Named constants rather than bare integers so the mapping
// below reads as the header does.
const (
	codeAuthenticationFailed  = -1
	codeUserCancel            = -2
	codeUserFallback          = -3
	codeSystemCancel          = -4
	codePasscodeNotSet        = -5
	codeBiometryNotAvailable  = -6
	codeBiometryNotEnrolled   = -7
	codeBiometryLockout       = -8
	codeAppCancel             = -9
	codeInvalidContext        = -10
	codeCompanionNotAvailable = -11
	codeBiometryNotPaired     = -12
	codeBiometryDisconnected  = -13
	codeInvalidDimensions     = -14
	codeNotInteractive        = -1004
)

// sentinels maps an LAError code to the exported error it unwraps to.
var sentinels = map[int]error{
	codeAuthenticationFailed:  ErrAuthenticationFailed,
	codeUserCancel:            ErrUserCancel,
	codeUserFallback:          ErrUserFallback,
	codeSystemCancel:          ErrSystemCancel,
	codePasscodeNotSet:        ErrPasscodeNotSet,
	codeBiometryNotAvailable:  ErrBiometryNotAvailable,
	codeBiometryNotEnrolled:   ErrBiometryNotEnrolled,
	codeBiometryLockout:       ErrBiometryLockout,
	codeAppCancel:             ErrAppCancel,
	codeInvalidContext:        ErrInvalidContext,
	codeCompanionNotAvailable: ErrCompanionNotAvailable,
	codeBiometryNotPaired:     ErrBiometryNotPaired,
	codeBiometryDisconnected:  ErrBiometryDisconnected,
	codeInvalidDimensions:     ErrInvalidDimensions,
	codeNotInteractive:        ErrNotInteractive,
}

// Error is a failure reported by LocalAuthentication. It keeps the raw LAError
// code and the system's own localised message — the sentence the user would
// have seen — and unwraps to the matching sentinel so errors.Is works.
type Error struct {
	// Op is the failing operation: "available" or "evaluate".
	Op string
	// Code is the raw LAError code (negative), or 0 when the framework
	// reported a failure without an NSError.
	Code int
	// Message is -[NSError localizedDescription], in the user's language. It
	// may be empty.
	Message string
	// Unbundled records that this process is not an .app bundle AND that the
	// failure is one a missing bundle identity could explain. When it is set
	// the error also unwraps to [ErrNotBundled].
	Unbundled bool
}

// Error implements the error interface.
func (e *Error) Error() string {
	msg := e.Message
	if msg == "" {
		msg = "no message"
	}
	s := fmt.Sprintf("localauthentication: %s: LAError %d: %s", e.Op, e.Code, msg)
	if e.Unbundled {
		s += " (this process is not an .app bundle, so LocalAuthentication has no application identity to show" +
			" — build one with github.com/go-macos/appbundle)"
	}
	return s
}

// Unwrap returns the sentinel for this error's LAError code and, when the
// process is unbundled and that could explain the failure, [ErrNotBundled] as
// well — so errors.Is finds either. An unrecognised code unwraps to nothing:
// the raw Code is then the only truth there is, and inventing a category for
// it would be a guess.
func (e *Error) Unwrap() []error {
	var errs []error
	if s, ok := sentinels[e.Code]; ok {
		errs = append(errs, s)
	}
	if e.Unbundled {
		errs = append(errs, ErrNotBundled)
	}
	return errs
}

// decided reports whether this LAError code means the dialog was actually
// shown and the person answered it. Those outcomes prove the system had an
// application identity to display, so the missing-bundle note must NOT be
// attached to them — it would be noise on top of a perfectly clear answer.
// Every other code is a setup failure, where an absent bundle is a real
// candidate cause.
func decided(code int) bool {
	switch code {
	case codeAuthenticationFailed, codeUserCancel, codeUserFallback, codeSystemCancel:
		return true
	default:
		return false
	}
}

// newError builds an [*Error], attaching the unbundled note where it could
// explain the failure.
func newError(op string, code int, message string) *Error {
	e := &Error{Op: op, Code: code, Message: message}
	if !decided(code) && unbundled() {
		e.Unbundled = true
	}
	return e
}

// options is the resolved set of [Option] values for one evaluation.
type options struct {
	fallbackTitle    string
	setFallbackTitle bool
	cancelTitle      string
	setCancelTitle   bool
	nonInteractive   bool
}

// Option customises the dialog, or suppresses it. Options are applied left to
// right and affect only the call they are passed to — each call builds its own
// LAContext.
type Option func(*options)

// WithFallbackTitle renames the dialog's fallback button, whose default title
// is "Use Password…". Passing "" HIDES the button, which is the way to offer
// biometrics with no escape hatch of the system's own; under
// [PolicyBiometrics] pressing it yields [ErrUserFallback], so hiding it removes
// an outcome the caller would otherwise have to handle.
func WithFallbackTitle(title string) Option {
	return func(o *options) { o.fallbackTitle, o.setFallbackTitle = title, true }
}

// WithCancelTitle renames the dialog's cancel button, whose default title is
// "Cancel". An empty title restores the default rather than hiding the button:
// a dialog the person cannot dismiss is not something this package will build.
func WithCancelTitle(title string) Option {
	return func(o *options) { o.cancelTitle, o.setCancelTitle = title, true }
}

// WithoutInteraction sets -[LAContext setInteractionNotAllowed:], so the
// evaluation fails with [ErrNotInteractive] INSTEAD of showing any UI.
//
// It is not a way to authenticate silently — nothing can — it is a way to
// exercise the full path (context, block, reply, error mapping) against the
// real framework with a guarantee that no prompt appears. That is how this
// package's own darwin tests run on a developer's laptop and on CI without
// ever putting a Touch ID sheet in front of anyone. It is also a legitimate
// probe in production: it distinguishes "the system would ask" from "the
// system would refuse before asking".
func WithoutInteraction() Option {
	return func(o *options) { o.nonInteractive = true }
}

// ---------------------------------------------------------------------------
// The seams. Everything above is portable; these two vars are the entire OS
// surface, assigned per platform (backend_darwin.go / backend_other.go). Tests
// replace them, which is what lets the logic here be covered on every lane —
// and, here, what guarantees that no test ever asks a real Secure Enclave
// anything.
// ---------------------------------------------------------------------------

// laContext is one LAContext, as narrow as this package needs it.
type laContext interface {
	// CanEvaluate is -canEvaluatePolicy:error:. On failure it reports the
	// NSError's code and localizedDescription, or (0, "") if there was no
	// NSError at all.
	CanEvaluate(policy int) (ok bool, code int, message string)
	// Biometry is the biometryType property. Apple only populates it after a
	// CanEvaluate call on the same context — see [Biometry].
	Biometry() int
	// Evaluate is -evaluatePolicy:localizedReason:reply:. It returns
	// immediately; reply is called once, later, on an unspecified thread.
	Evaluate(policy int, reason string, reply func(ok bool, code int, message string))
	// Invalidate is -invalidate: it terminates an evaluation in progress,
	// whose reply then arrives with LAErrorAppCancel.
	Invalidate()
	// Release drops this package's reference to the context.
	Release()
}

var (
	// newContext builds a configured LAContext, or reports why it could not.
	newContext = platformNewContext
	// unbundled reports whether this process lacks a bundle identifier.
	unbundled = platformUnbundled
)

// ---------------------------------------------------------------------------
// The API.
// ---------------------------------------------------------------------------

// Biometry reports which biometric sensor this Mac has: [BiometryTouchID], or
// [BiometryNone] on a Mac without one (or where this process may not use it).
//
// The trap it works around: -[LAContext biometryType] is only populated AFTER
// -canEvaluatePolicy: has been called on that same context. Read straight after
// init it reports None on a machine with a perfectly good Touch ID sensor, and
// nothing tells you why. So this calls CanEvaluate first and discards its
// answer — the sensor's existence is a different question from whether it can
// be used right now, which is [Available]'s.
//
// It shows no UI.
func Biometry() (BiometryType, error) {
	c, err := newContext(options{})
	if err != nil {
		return BiometryNone, err
	}
	defer c.Release()
	c.CanEvaluate(int(PolicyBiometrics))
	return BiometryType(c.Biometry()), nil
}

// Available reports whether policy could be evaluated right now, returning nil
// if it could and a [*Error] saying why not if it could not — no enrolled
// finger ([ErrBiometryNotEnrolled]), a locked-out sensor
// ([ErrBiometryLockout]), no password set ([ErrPasscodeNotSet]).
//
// It shows no UI and has no side effect, so it is the right call for deciding
// whether to draw an "Unlock with Touch ID" button at all. Its answer is a
// snapshot: consume it now rather than caching it, because a finger can be
// enrolled, or a sensor locked out, between this call and the next.
//
// A policy this package does not define is rejected with [ErrInvalidPolicy]
// before the framework is reached — LAContext throws for one, and that throw
// kills the process.
//
// Apple warns that calling it from inside an evaluation's reply block can
// deadlock. This package never does, and neither should you.
func Available(policy Policy) error {
	if !policy.valid() {
		return fmt.Errorf("%w: %d", ErrInvalidPolicy, int(policy))
	}
	c, err := newContext(options{})
	if err != nil {
		return err
	}
	defer c.Release()
	if ok, code, message := c.CanEvaluate(int(policy)); !ok {
		return newError("available", code, message)
	}
	return nil
}

// Evaluate asks the person at the keyboard to authenticate under policy, and
// BLOCKS until they answer. It returns nil when the system attests that they
// did, and otherwise a [*Error] that unwraps to the sentinel for what happened
// — see the package comment for why that is not a boolean.
//
// reason is shown to the person, completing the sentence «AppName» is trying
// to <reason>. Write it as a verb phrase ("unlock this document"), lower case,
// no trailing full stop. It must not be empty: the framework raises
// NSInvalidArgumentException for an empty reason and that exception kills the
// process, so [ErrEmptyReason] is returned before the framework is reached.
//
// Cancelling ctx invalidates the context, which terminates the evaluation and
// dismisses the dialog; Evaluate then returns ctx.Err(). A ctx already
// cancelled on entry means no prompt is ever shown.
//
// A policy this package does not define is rejected with [ErrInvalidPolicy]
// before the framework is reached, for the same reason an empty reason is: the
// framework's answer to either is an Objective-C exception, not an error.
//
// ⚠ It prompts, and it blocks. Do not call it on a GUI program's main thread —
// see the package comment.
func Evaluate(ctx context.Context, policy Policy, reason string, opts ...Option) error {
	if !policy.valid() {
		return fmt.Errorf("%w: %d", ErrInvalidPolicy, int(policy))
	}
	if reason == "" {
		return ErrEmptyReason
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	c, err := newContext(o)
	if err != nil {
		return err
	}
	defer c.Release()
	// Checked before prompting, so a caller whose context is already dead
	// never puts a dialog on screen that it will immediately tear down.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Buffered, and deliberately: on the cancellation path Evaluate returns
	// without draining, and the reply — which arrives later, with
	// LAErrorAppCancel — must not block the framework's private queue on a
	// send nobody is receiving.
	done := make(chan error, 1)
	c.Evaluate(int(policy), reason, func(ok bool, code int, message string) {
		if ok {
			done <- nil
			return
		}
		done <- newError("evaluate", code, message)
	})

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		c.Invalidate()
		return ctx.Err()
	}
}
