// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package localauthentication

// Away from macOS there is no LocalAuthentication and no Secure Enclave to ask.
// The seams answer that they cannot, rather than being absent: a consumer that
// cross-compiles gets the same API and one clean error out of it, instead of a
// build that fails on a platform where the feature was never going to exist.

// platformNewContext reports [ErrUnsupported] off darwin.
func platformNewContext(options) (laContext, error) { return nil, ErrUnsupported }

// platformUnbundled reports false off darwin: there are no .app bundles, so
// the missing-bundle note would be meaningless noise on an unrelated error.
func platformUnbundled() bool { return false }
