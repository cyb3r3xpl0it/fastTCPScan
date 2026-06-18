//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// checkFDLimit ajusta -threads si supera el límite de descriptores de archivo del sistema.
func checkFDLimit() {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return
	}
	const margin = 64 // descriptores reservados para stdio, archivos, etc.
	safe := int(rl.Cur) - margin
	if safe < 1 {
		safe = 1
	}
	if *threads > safe {
		fmt.Fprintf(os.Stderr, "[!] -threads=%d supera el límite de descriptores (ulimit -n=%d); ajustado a %d\n",
			*threads, rl.Cur, safe)
		*threads = safe
	}
}

// isTooManyFiles indica si el error se debe al agotamiento de descriptores de archivo.
func isTooManyFiles(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}
