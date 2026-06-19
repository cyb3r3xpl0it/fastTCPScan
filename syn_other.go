//go:build !linux

package main

import "context"

// synProbe no está soportado fuera de Linux; main valida esto antes de escanear.
func synProbe(ctx context.Context, j job) Result {
	return Result{Host: j.host, Port: j.port, Proto: "tcp", State: "closed"}
}
