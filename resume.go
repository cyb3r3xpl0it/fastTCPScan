package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	ckptDone map[string]bool // jobs ya completados (host/puerto)
	ckptFile *os.File        // archivo de checkpoint abierto en modo append
	ckptMu   sync.Mutex
)

// jobKey identifica de forma única un job (host + puerto).
func jobKey(host string, port int) string {
	return host + "/" + strconv.Itoa(port)
}

// loadCheckpoint lee un checkpoint previo y devuelve los puertos abiertos ya hallados.
func loadCheckpoint(path string) ([]Result, error) {
	ckptDone = make(map[string]bool)

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // primera ejecución, sin checkpoint
		}
		return nil, err
	}
	defer f.Close()

	var prev []Result
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Result
		if err := json.Unmarshal(line, &r); err != nil {
			continue // ignoramos líneas corruptas
		}
		ckptDone[jobKey(r.Host, r.Port)] = true
		if strings.HasPrefix(r.State, "open") {
			prev = append(prev, r)
		}
	}
	return prev, sc.Err()
}

// openCheckpoint abre (o crea) el archivo de checkpoint en modo append.
func openCheckpoint(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	ckptFile = f
	return nil
}

// recordCheckpoint persiste un resultado completado (abierto o cerrado).
func recordCheckpoint(r Result) {
	if ckptFile == nil {
		return
	}
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	ckptMu.Lock()
	ckptFile.Write(b)
	ckptFile.Write([]byte("\n"))
	ckptMu.Unlock()
}

func closeCheckpoint() {
	if ckptFile != nil {
		ckptFile.Close()
	}
}
