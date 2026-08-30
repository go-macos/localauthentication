// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package localauthentication

import (
	"context"
	"errors"
	"testing"
)

// Away from macOS every entry point must report ErrUnsupported while the
// package still builds, so a consumer cross-compiles and gets one clean error
// instead of a build failure on a platform where a Secure Enclave was never
// going to exist.
func TestUnsupported(t *testing.T) {
	if _, err := Biometry(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Biometry error = %v, want ErrUnsupported", err)
	}
	if err := Available(PolicyOwner); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Available error = %v, want ErrUnsupported", err)
	}
	if err := Evaluate(context.Background(), PolicyOwner, "unlock"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Evaluate error = %v, want ErrUnsupported", err)
	}
}

// TestUnbundledIsFalseOffDarwin: there are no .app bundles here, so attaching
// the appbundle note to an unrelated error would be noise.
func TestUnbundledIsFalseOffDarwin(t *testing.T) {
	if platformUnbundled() {
		t.Fatal("platformUnbundled = true off darwin")
	}
}

// TestGuardsFireBeforeTheUnsupportedStub: the empty-reason and unknown-policy
// guards are portable, so they answer here too — and they answer FIRST, which
// is what makes them guards rather than decoration.
func TestGuardsFireBeforeTheUnsupportedStub(t *testing.T) {
	if err := Evaluate(context.Background(), PolicyOwner, ""); !errors.Is(err, ErrEmptyReason) {
		t.Errorf("Evaluate(\"\") = %v, want ErrEmptyReason", err)
	}
	if err := Evaluate(context.Background(), Policy(9999), "unlock"); !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("Evaluate(9999) = %v, want ErrInvalidPolicy", err)
	}
	if err := Available(Policy(9999)); !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("Available(9999) = %v, want ErrInvalidPolicy", err)
	}
}
