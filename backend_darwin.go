// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package localauthentication

import (
	"fmt"
	"sync"

	"github.com/go-macos/objc"
)

// This file is the whole OS surface: LAContext reached by Objective-C message
// send through github.com/go-macos/objc, which is purego underneath — no cgo.
//
// Unlike the Keychain (plain C functions over CFDictionary, bound with
// dlsym/RegisterFunc), LocalAuthentication is Objective-C only: LAContext is a
// class, everything on it is a message, and the completion handler is a BLOCK.
// So this goes through the objc bridge rather than binding C symbols.

// localAuthentication is the framework this package needs. Foundation comes
// with it for NSString, NSError and NSBundle.
const localAuthentication = "/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication"

// Selectors, resolved once through objc's cache. Named here so a typo is a
// compile-time symbol and not a silent no-op at run time.
var (
	selAlloc            = objc.Sel("alloc")
	selInit             = objc.Sel("init")
	selRetain           = objc.Sel("retain")
	selRelease          = objc.Sel("release")
	selInvalidate       = objc.Sel("invalidate")
	selCanEvaluate      = objc.Sel("canEvaluatePolicy:error:")
	selEvaluate         = objc.Sel("evaluatePolicy:localizedReason:reply:")
	selBiometryType     = objc.Sel("biometryType")
	selSetFallbackTitle = objc.Sel("setLocalizedFallbackTitle:")
	selSetCancelTitle   = objc.Sel("setLocalizedCancelTitle:")
	selSetNoInteraction = objc.Sel("setInteractionNotAllowed:")
	selCode             = objc.Sel("code")
	selLocalizedDesc    = objc.Sel("localizedDescription")
	selMainBundle       = objc.Sel("mainBundle")
	selBundleIdentifier = objc.Sel("bundleIdentifier")
)

// The seams BELOW the objc bridge. They are package vars for one reason: every
// branch here is a failure branch — a framework that will not load, a class the
// runtime does not know, an -init that answers nil — and none of them can be
// provoked on a Mac where all three work. Tests replace these; nothing else
// does.
var (
	loadOnce = new(sync.Once)
	loadErr  error

	// laLoad dlopens Foundation and LocalAuthentication.
	laLoad = func() error { return objc.Load(objc.Foundation, localAuthentication) }
	// laClass looks up the LAContext class.
	laClass = func() objc.ID { return objc.ClassID("LAContext") }
	// laAlloc builds one LAContext instance (+1 retained, as alloc/init is).
	laAlloc = func(cls objc.ID) objc.ID { return cls.Send(selAlloc).Send(selInit) }
	// mainBundle is +[NSBundle mainBundle].
	mainBundle = func() objc.ID { return objc.ClassID("NSBundle").Send(selMainBundle) }
)

// bundleIdentifier reads this process's CFBundleIdentifier, "" when there is
// none — which is the case for anything `go build` produces and runs directly.
func bundleIdentifier() string {
	bundle := mainBundle()
	if bundle == 0 {
		return ""
	}
	return objc.GoString(bundle.Send(selBundleIdentifier))
}

// load resolves the frameworks once, remembering the failure if there was one.
func load() error {
	loadOnce.Do(func() {
		if err := laLoad(); err != nil {
			loadErr = fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
	})
	return loadErr
}

// darwinContext is one live LAContext.
type darwinContext struct{ id objc.ID }

// platformNewContext builds and configures an LAContext.
//
// Every object it obtains is checked for nil. A message to nil in Objective-C
// returns zero and says nothing at all, so an unchecked nil class here would
// not fail: it would produce a context that answers "not available" to every
// question, forever, with no explanation anywhere. Each nil is reported as
// [ErrUnavailable] naming the step that produced it.
func platformNewContext(o options) (laContext, error) {
	if err := load(); err != nil {
		return nil, err
	}
	cls := laClass()
	if cls == 0 {
		return nil, fmt.Errorf("%w: the LAContext class is not registered in this process", ErrUnavailable)
	}
	id := laAlloc(cls)
	if id == 0 {
		return nil, fmt.Errorf("%w: -[LAContext init] returned nil", ErrUnavailable)
	}

	// The titles are set as autoreleased NSStrings the context copies (both
	// properties are `copy`), so nothing here has to outlive the call.
	if o.setFallbackTitle {
		id.Send(selSetFallbackTitle, objc.NSString(o.fallbackTitle))
	}
	if o.setCancelTitle {
		id.Send(selSetCancelTitle, objc.NSString(o.cancelTitle))
	}
	if o.nonInteractive {
		id.Send(selSetNoInteraction, true)
	}
	return &darwinContext{id: id}, nil
}

// platformUnbundled reports whether this process has no bundle identifier —
// a bare `go build` binary, as opposed to something run from inside an .app.
// It is what puts the appbundle hint on an error rather than leaving the caller
// to wonder.
func platformUnbundled() bool {
	if load() != nil {
		return false
	}
	return bundleIdentifier() == ""
}

// errorInfo reads an NSError's code and localizedDescription. The nil NSError
// yields (0, ""): the framework is documented to set the out-parameter on
// failure, but it is an out-parameter, and a nil one dereferenced would be a
// crash rather than an error message.
func errorInfo(nsErr objc.ID) (int, string) {
	if nsErr == 0 {
		return 0, ""
	}
	return objc.Send[int](nsErr, selCode), objc.Stringify(nsErr.Send(selLocalizedDesc))
}

// CanEvaluate sends -canEvaluatePolicy:error:.
//
// The out-parameter is a Go *objc.ID. objc.ID is uintptr-shaped, so what
// Objective-C writes through the pointer is a plain word the collector has no
// reason to trace — there is no Go pointer being stored into C-visible memory,
// and the NSError it names is autoreleased by the framework.
func (c *darwinContext) CanEvaluate(policy int) (bool, int, string) {
	var nsErr objc.ID
	// Send[bool] reads the LOW BYTE of the return register, which is what a
	// BOOL is. Asking for an int here would read whatever the upper bits happen
	// to hold — the ABI does not promise they are clear — and could turn NO
	// into a nonzero "yes". That is the kind of mistake that only shows up on
	// somebody else's Mac.
	ok := objc.Send[bool](c.id, selCanEvaluate, policy, &nsErr)
	// Read unconditionally: on success the framework leaves the out-parameter
	// nil and errorInfo answers (0, ""). Branching on ok here would leave one
	// arm of this function exercised only on a machine that HAS the hardware,
	// which is not a property a test suite should depend on.
	code, message := errorInfo(nsErr)
	return ok, code, message
}

// Biometry reads the biometryType property. It is meaningful only after a
// CanEvaluate on this same context — the portable [Biometry] arranges that.
func (c *darwinContext) Biometry() int { return objc.Send[int](c.id, selBiometryType) }

// Evaluate sends -evaluatePolicy:localizedReason:reply: with a real
// Objective-C block.
//
// Three lifetimes have to be got right, and each of them is a crash or a leak
// if it is not:
//
//   - The BLOCK. objc.NewBlock keeps the Go closure alive in a process-wide
//     cache keyed by the block pointer; only Release drops it. The block's own
//     self pointer arrives as the callback's FIRST parameter (that is the block
//     ABI, and purego panics if the first parameter is anything else), which is
//     how it releases itself from inside the handler without capturing itself.
//   - The CONTEXT. Apple: "be sure to keep a strong reference to the context
//     while the evaluation is in progress, otherwise an evaluation would be
//     cancelled when the context is being deallocated." The caller's
//     defer Release() may well run first — on the cancellation path it always
//     does — so this retains a second reference and drops it in the reply.
//   - The REASON string. objc.NSString is autoreleased, and the evaluation
//     outlives this frame, so it is retained here and released in the reply
//     rather than trusted to a pool that may not exist on this thread.
//
// The reply runs on a private framework queue, on a thread Go did not create.
// A purego callback there is entered through the runtime's cgocallback path, so
// the channel send the handler performs is a normal one.
func (c *darwinContext) Evaluate(policy int, reason string, reply func(bool, int, string)) {
	c.id.Send(selRetain)
	reasonStr := objc.NSString(reason).Send(selRetain)

	block := objc.NewBlock(func(self objc.Block, success bool, nsErr objc.ID) {
		code, message := errorInfo(nsErr)
		reply(success, code, message)
		reasonStr.Send(selRelease)
		c.id.Send(selRelease)
		self.Release()
	})
	c.id.Send(selEvaluate, policy, reasonStr, block)
}

// Invalidate sends -invalidate, terminating any evaluation in progress; its
// reply then arrives with LAErrorAppCancel, which is what releases the block,
// the reason string and this method's retained reference.
func (c *darwinContext) Invalidate() { c.id.Send(selInvalidate) }

// Release drops the reference alloc/init gave us.
func (c *darwinContext) Release() { c.id.Send(selRelease) }
