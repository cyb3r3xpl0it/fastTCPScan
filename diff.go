package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func diffKey(host string, port int, proto string) string {
	return host + "/" + proto + "/" + strconv.Itoa(port)
}

// loadPreviousScan carga los puertos abiertos de un escaneo JSON previo (de -format json).
func loadPreviousScan(path string) (map[string]Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer %q: %v", path, err)
	}
	var prev []Result
	if err := json.Unmarshal(data, &prev); err != nil {
		return nil, fmt.Errorf("%q no es un JSON de escaneo válido: %v", path, err)
	}
	m := make(map[string]Result, len(prev))
	for _, r := range prev {
		if strings.HasPrefix(r.State, "open") {
			m[diffKey(r.Host, r.Port, r.Proto)] = r
		}
	}
	return m, nil
}

// closedSince devuelve los puertos que estaban abiertos antes y ya no aparecen.
func closedSince(prev map[string]Result, current []Result) []Result {
	curKeys := make(map[string]bool, len(current))
	for _, r := range current {
		curKeys[diffKey(r.Host, r.Port, r.Proto)] = true
	}
	var closed []Result
	for k, r := range prev {
		if !curKeys[k] {
			r.State = "closed"
			closed = append(closed, r)
		}
	}
	return closed
}
