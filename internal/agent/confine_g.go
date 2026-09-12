//go:build linux || darwin

package agent

import "runtime"

func runtimeGOOSConfine() string { return runtime.GOOS }
