package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// profiles son conjuntos de opciones predefinidas seleccionables con -profile.
var profiles = map[string]map[string]string{
	"fast":    {"top": "100", "timeout": "500ms", "threads": "2000"},
	"full":    {"range": "1-65535", "timeout": "1s", "threads": "1000"},
	"stealth": {"rate": "50", "randomize": "true", "timeout": "2s", "threads": "100"},
	"web":     {"range": "80,443,3000,5000,8000,8080,8443,8888", "sV": "true", "banner": "true"},
}

func profileNames() string {
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// applySettings aplica el perfil y el archivo de config sin pisar los flags explícitos.
// Precedencia: línea de comandos > -config > -profile > valores por defecto.
func applySettings(explicit map[string]bool) error {
	if *profile != "" {
		p, ok := profiles[*profile]
		if !ok {
			return fmt.Errorf("perfil desconocido %q (disponibles: %s)", *profile, profileNames())
		}
		if err := applyKV(p, explicit); err != nil {
			return err
		}
	}
	if *configFile != "" {
		kv, err := readConfig(*configFile)
		if err != nil {
			return err
		}
		if err := applyKV(kv, explicit); err != nil {
			return err
		}
	}
	return nil
}

func applyKV(kv map[string]string, explicit map[string]bool) error {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys) // orden estable para errores reproducibles
	for _, k := range keys {
		if explicit[k] {
			continue // lo definido en la línea de comandos manda
		}
		if flag.Lookup(k) == nil {
			return fmt.Errorf("opción desconocida %q", k)
		}
		if err := flag.Set(k, kv[k]); err != nil {
			return fmt.Errorf("valor inválido para %q: %v", k, err)
		}
	}
	return nil
}

// readConfig lee un archivo "clave = valor" (ignora líneas vacías y comentarios # o ;).
func readConfig(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir el config %q: %v", path, err)
	}
	defer f.Close()

	kv := map[string]string{}
	sc := bufio.NewScanner(f)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("%s:%d línea inválida (se esperaba clave = valor): %q", path, ln, line)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.Trim(strings.TrimSpace(line[eq+1:]), `"'`)
		kv[key] = val
	}
	return kv, sc.Err()
}
