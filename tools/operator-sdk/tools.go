// SPDX-FileCopyrightText: Chirag Rao <crao@redhat.com>
//
// SPDX-License-Identifier: CC0-1.0

//go:build tools
// +build tools

// Tracks in a separate module to avoid dependency conflicts with the main module.

package tools

import _ "github.com/operator-framework/operator-sdk/cmd/operator-sdk"
