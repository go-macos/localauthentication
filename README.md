# localauthentication

[![CI](https://github.com/go-macos/localauthentication/actions/workflows/ci.yml/badge.svg)](https://github.com/go-macos/localauthentication/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-macos/localauthentication.svg)](https://pkg.go.dev/github.com/go-macos/localauthentication)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](.github/workflows/ci.yml)

Ask macOS to authenticate the person at the keyboard — **Touch ID**, or the
login password — from pure Go with `CGO_ENABLED=0`.

It binds `LAContext` through [`go-macos/objc`](https://github.com/go-macos/objc)
(Objective-C message sends over
[`ebitengine/purego`](https://github.com/ebitengine/purego)), so it links with
**no cgo** and shells out to nothing.

```go
import "github.com/go-macos/localauthentication"

// Is there a sensor, and of what kind? (No prompt.)
kind, err := localauthentication.Biometry()          // "Touch ID" / "none"

// Could this be evaluated right now? (No prompt, no side effect.)
err = localauthentication.Available(localauthentication.PolicyBiometrics)

// Ask. THIS PROMPTS, and it blocks until they answer.
err = localauthentication.Evaluate(ctx,
    localauthentication.PolicyOwner, "unlock this document")
```

## What it is

A biometric check is not something a program implements. The fingerprint never
leaves the Secure Enclave; nothing in your process, or in the kernel, ever sees
it. What LocalAuthentication returns is an **attestation** — the system saying
the device owner was present and identified themselves. This package asks for
that attestation and reports faithfully what came back.

It is therefore a gate on **convenience**, not a cryptographic control: anything
that can patch your process can skip it. Data that must actually stay secret
belongs in the Keychain behind a `SecAccessControl` — see
[Relationship with `go-macos/keychain`](#relationship-with-go-macoskeychain).

## Policies

| Constant | LAPolicy | Behaviour |
| --- | --- | --- |
| `PolicyBiometrics` | `LAPolicyDeviceOwnerAuthenticationWithBiometrics` (**1**) | Touch ID and nothing else. Unavailable, unenrolled or locked-out biometry **fails** rather than falling back. "Use Password…" ends the evaluation with `ErrUserFallback`. |
| `PolicyOwner` | `LAPolicyDeviceOwnerAuthentication` (**2**) | Touch ID **or** the account password. If biometry cannot be used the password is asked for straight away, and "Use Password…" switches the same dialog over instead of ending it. |

The values are **1 and 2** — read out of `LAPublicDefines.h` in the macOS SDK,
not from memory. (0 and 1 is the pair people misremember; there is no LAPolicy
0, and passing one is not a mistake the framework forgives — see below.)

Any other policy value is rejected with `ErrInvalidPolicy` **before** the
framework is reached.

## A `bool` would be a lie

`Evaluate` returns an `error`, because "it did not succeed" covers a dozen
situations a caller must treat differently. Every failure is an `*Error`
carrying the raw LAError code and the system's own localised message, and it
unwraps to a sentinel, so `errors.Is` answers the question you actually have
while `errors.As` keeps the detail for a log.

| Sentinel | LAError | What it means for the caller |
| --- | --- | --- |
| `ErrAuthenticationFailed` | -1 | Wrong finger or wrong password. They are present and trying; another attempt is reasonable. |
| `ErrUserCancel` | -2 | They pressed Cancel. A decision. Do not re-prompt. |
| `ErrUserFallback` | -3 | They pressed "Use Password…" under `PolicyBiometrics`, which **ends** the evaluation. Offer your own route, or re-evaluate under `PolicyOwner`. |
| `ErrSystemCancel` | -4 | The system interrupted — another app came forward, the screen locked. Nobody decided anything. |
| `ErrPasscodeNotSet` | -5 | No account password, so `PolicyOwner` has nothing to fall back to. |
| `ErrBiometryNotAvailable` | -6 | No usable sensor. Stop offering the option this session. |
| `ErrBiometryNotEnrolled` | -7 | A sensor, but no enrolled finger. Worth saying — they can fix it in System Settings. |
| `ErrBiometryLockout` | -8 | Five failures; the sensor is locked until the account password is entered. Retrying biometrics is pointless — re-evaluate `PolicyOwner`, which unlocks it as a side effect. |
| `ErrAppCancel` | -9 | Your own cancellation (a cancelled `context`). |
| `ErrInvalidContext` | -10 | The `LAContext` was already invalidated. |
| `ErrCompanionNotAvailable` | -11 | No paired Apple Watch nearby. |
| `ErrBiometryNotPaired` | -12 | Biometry lives on a removable accessory that was never paired. |
| `ErrBiometryDisconnected` | -13 | That accessory is paired but not connected. |
| `ErrInvalidDimensions` | -14 | Invalid embedded-UI dimensions. Not reachable through this package. |
| `ErrNotInteractive` | -1004 | UI was required but forbidden — you passed `WithoutInteraction()`. |

Plus, before the framework is reached: `ErrEmptyReason`, `ErrInvalidPolicy`,
`ErrUnavailable`, `ErrUnsupported`, and `ErrNotBundled` (attached to a failure,
never on its own).

An LAError this package does not recognise unwraps to **nothing**. The raw
`Code` and `Message` are then the only truth there is, and inventing a category
for it would be a guess.

## The hard parts, honestly

### The reply is an Objective-C block — and that worked

`-evaluatePolicy:localizedReason:reply:` is asynchronous and takes a **block**,
not a function pointer. It was worth checking whether purego could carry that
before designing around it: it can. `go-macos/objc` exposes `NewBlock`, and the
darwin backend passes a real block whose Go closure hands the result back over a
channel. Nothing is faked, nothing is polled, and there is no fallback API here
because none was needed.

Three lifetimes have to be right, and each is a crash or a leak if it is not:
the **block** (released from inside the handler via its own `self` pointer,
which the block ABI passes as the callback's first parameter), the **context**
(retained for the evaluation, because Apple cancels an evaluation whose context
is deallocated), and the **reason string** (retained rather than trusted to an
autorelease pool that may not exist on the calling thread).

`Evaluate` is nonetheless **synchronous**: the answer decides what happens next,
so the caller wants to wait for it. Apple documents the reply as arriving on a
private framework queue, so no run loop of yours has to be turning.

> ⚠ Do not call `Evaluate` on a GUI program's blocked main thread. Call it from
> a goroutine and post the result back with `objc.DispatchMain`.

Cancelling the `context` invalidates the `LAContext`, which dismisses the sheet;
`Evaluate` then returns `ctx.Err()`, and the late reply is absorbed by a
buffered channel so the framework's queue is never stuck on a send nobody is
receiving.

### It wants an `.app` bundle

LocalAuthentication identifies the asking program by its bundle: the prompt
reads *«AppName» is trying to \<your reason\>*. A bare `go build` binary has no
bundle identifier, and evaluation from one is unreliable.

Build a real bundle with
[`go-macos/appbundle`](https://github.com/go-macos/appbundle) and run from
inside it. When a failure arrives **and** this process is not bundled, the
`*Error` says so: its `Unbundled` field is set, it unwraps to `ErrNotBundled`,
and `Error()` names appbundle. The note is attached only to setup failures —
never to `ErrUserCancel`, `ErrUserFallback`, `ErrAuthenticationFailed` or
`ErrSystemCancel`, because those prove the dialog appeared and the identity
plainly worked.

### Two calls into this framework kill your process

Neither returns an error. Both raise `NSInvalidArgumentException`, and an
Objective-C exception unwinding through a purego frame is **not** a Go panic —
there is no `recover()` for it, the process aborts:

- an **empty `localizedReason`** to `evaluatePolicy:`;
- a **policy the framework does not know** to `canEvaluatePolicy:` — which is
  how `ErrInvalidPolicy` came to exist here. It was found by a test that passed
  `9999` and took the whole test binary down with
  `Error Domain=com.apple.LocalAuthentication Code=-1001 "Unknown policy: '9999'"`.

Both are guarded in the portable layer, before any message is sent.

### `biometryType` is empty until you ask something else

`-[LAContext biometryType]` is only populated **after** `canEvaluatePolicy:` has
been called on that same context. Read straight after `init` it reports `none`
on a Mac with a perfectly good Touch ID sensor, and nothing tells you why.
`Biometry()` makes that call first and discards its answer.

## Testing: no test may raise a prompt

The portable logic is covered on every platform through an injected seam that
replaces `LAContext` entirely.

The **darwin** tests go further: they message a real `LAContext`, resolve real
selectors, and run a real Objective-C block end to end. None of them can raise a
prompt, and that rests on two guarantees out of Apple's own headers rather than
on hope:

- an **invalidated** context "can not be used for policy evaluation and an
  attempt to do so will fail with `LAErrorInvalidContext`" — there is nothing
  left to draw a dialog with;
- `interactionNotAllowed` makes an evaluation "fail with `LAErrorNotInteractive`
  **instead of displaying the authentication UI**" — exposed as
  `WithoutInteraction()`, which is both the safety belt and a legitimate probe.

Machine-dependent answers are asserted on their *shape* — "the framework
answered with an error we recognise" — never on the hardware the test happens to
run on, so a CI runner with no Touch ID and a laptop with one both pass for the
right reason.

The one test that really prompts is opt-in:

```sh
CGO_ENABLED=0 go test ./...                              # 100% coverage, never prompts
LOCALAUTH_LIVE_PROMPT=1 go test -run TestLivePrompt -v   # asks you for real
```

## Relationship with `go-macos/keychain`

Deliberately, none in code. The two solve different halves and the boundary is
worth stating.

[`go-macos/keychain`](https://github.com/go-macos/keychain) can already store an
item behind a `SecAccessControl` with `kSecAccessControlUserPresence`, and
**reading such an item prompts for Touch ID by itself** — the Keychain asks
LocalAuthentication on your behalf and nothing in this package is involved:

```go
keychain.Set("my-app", "alice", secret, keychain.WithAccessControl(keychain.UserPresence))
secret, err := keychain.Get("my-app", "alice")   // prompts; enforced by the Keychain
```

That is the **stronger** arrangement, because the secret is genuinely unreadable
until the attestation is made, rather than merely being guarded by a check that
code could skip. If you have a secret, use that.

This package is for the other case: gating an action that has no secret behind
it — reopening a document already decrypted in memory, revealing a field,
confirming a destructive step.

There *is* one real seam between the two, and it is **not implemented**:
`LAContext` can be passed to a Keychain query as `kSecUseAuthenticationContext`,
so one successful evaluation authorises a subsequent read without a second
prompt. That means exposing a live `LAContext` across a package boundary and
agreeing on its lifetime; it belongs in whichever package owns the query, and it
should be designed rather than fallen into.

## How the PDF reader will use it

[`go-pdfkit`](https://github.com/go-pdfkit)'s reader wants biometric unlock for
a protected document. It does not need to change for this package to exist —
this is the shape it will take:

```go
// At startup, once: decide whether to draw the button at all.
canUseTouchID := localauthentication.Available(localauthentication.PolicyOwner) == nil

// When the person opens a protected document, from a goroutine — never from
// the blocked main thread.
go func() {
    err := localauthentication.Evaluate(ctx, localauthentication.PolicyOwner,
        "unlock this document")
    objc.DispatchMain(func() {
        switch {
        case err == nil:
            reveal(doc)
        case errors.Is(err, localauthentication.ErrUserCancel):
            // They said no. Leave the document closed, say nothing.
        case errors.Is(err, localauthentication.ErrBiometryLockout):
            askForPassphrase("Touch ID is locked; enter your document password")
        case errors.Is(err, localauthentication.ErrNotBundled):
            log.Printf("not running from an .app bundle: %v", err)
            askForPassphrase("")
        default:
            askForPassphrase("")
        }
    })
}()
```

The document's own passphrase stays the real protection; this only decides
whether the reader has to ask for it again. If the reader ever wants to *keep* a
passphrase, that belongs in `go-macos/keychain` with
`WithAccessControl(UserPresence)`, not here.

The reader must be a real `.app` — which it already is, built with
`go-macos/appbundle`.

## Platforms

Darwin only. Every exported symbol is defined on every platform so consumers
cross-compile; off darwin each entry point returns `ErrUnsupported`. CI builds
the darwin backend for amd64 and arm64 and the stub for six 64-bit targets.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
