package main

import "testing"

// FuzzExpandPorts comprueba que el parser de puertos nunca entra en pánico
// y que, cuando tiene éxito, solo devuelve puertos válidos (1-65535).
func FuzzExpandPorts(f *testing.F) {
	seeds := []string{"80", "1-100", "80,443", "1-65535", " 22 , 22 ", "3-1", "", "abc", "0", "70000", "10-"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		ports, err := expandPorts(in)
		if err != nil {
			return
		}
		seen := make(map[int]bool, len(ports))
		for _, p := range ports {
			if p < 1 || p > 65535 {
				t.Fatalf("expandPorts(%q) devolvió un puerto fuera de rango: %d", in, p)
			}
			if seen[p] {
				t.Fatalf("expandPorts(%q) devolvió el puerto %d duplicado", in, p)
			}
			seen[p] = true
		}
	})
}

// FuzzExpandCIDR comprueba que el parser de CIDR nunca entra en pánico.
func FuzzExpandCIDR(f *testing.F) {
	seeds := []string{"10.0.0.0/30", "192.168.1.0/24", "10.0.0.5/32", "0.0.0.0/0", "::1/128", "abc", "10.0.0.0/99"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		ips, err := expandCIDR(in)
		if err != nil {
			return
		}
		if len(ips) > 1<<20 {
			t.Fatalf("expandCIDR(%q) devolvió demasiadas direcciones: %d", in, len(ips))
		}
	})
}

// FuzzParseProxy comprueba que el parser de proxy nunca entra en pánico.
func FuzzParseProxy(f *testing.F) {
	seeds := []string{"127.0.0.1:1080", "socks5://10.0.0.1:9050", "user:pass@host:1080", "", "@", "x"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = parseProxy(in)
	})
}

// FuzzSanitize comprueba que sanitize nunca entra en pánico y acota la longitud.
func FuzzSanitize(f *testing.F) {
	f.Add("hola\r\nmundo")
	f.Add("\x00\x01\x02")
	f.Fuzz(func(t *testing.T, in string) {
		out := sanitize(in)
		if len([]rune(out)) > 81 {
			t.Fatalf("sanitize devolvió una cadena demasiado larga: %d runas", len([]rune(out)))
		}
	})
}
