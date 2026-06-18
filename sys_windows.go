//go:build windows

package main

// En Windows no existe RLIMIT_NOFILE; no hay ajuste automático de concurrencia.
func checkFDLimit() {}

// isTooManyFiles no aplica en Windows.
func isTooManyFiles(err error) bool { return false }
