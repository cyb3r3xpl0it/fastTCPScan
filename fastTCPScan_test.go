package main

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestExpandPorts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"80", []int{80}},
		{"80,443", []int{80, 443}},
		{"1-3", []int{1, 2, 3}},
		{"1-3,2-4", []int{1, 2, 3, 4}}, // deduplicación
		{"3-1", []int{1, 2, 3}},        // rango invertido
		{" 80 , 443 ", []int{80, 443}}, // espacios
		{"22,22,22", []int{22}},        // duplicados exactos
		{"65535", []int{65535}},        // límite superior
	}
	for _, c := range cases {
		got, err := expandPorts(c.in)
		if err != nil {
			t.Errorf("expandPorts(%q) error inesperado: %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("expandPorts(%q) = %v, se esperaba %v", c.in, got, c.want)
		}
	}
}

func TestExpandPortsErrors(t *testing.T) {
	for _, in := range []string{"", "abc", "0", "70000", "1-99999", "10-abc"} {
		if _, err := expandPorts(in); err == nil {
			t.Errorf("expandPorts(%q) debería devolver error", in)
		}
	}
}

func TestExpandCIDR(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"192.168.1.0/30", []string{"192.168.1.1", "192.168.1.2"}}, // descarta red y broadcast
		{"192.168.1.0/31", []string{"192.168.1.0", "192.168.1.1"}}, // /31 sin descarte
		{"10.0.0.5/32", []string{"10.0.0.5"}},                      // host único
	}
	for _, c := range cases {
		got, err := expandCIDR(c.in)
		if err != nil {
			t.Errorf("expandCIDR(%q) error inesperado: %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("expandCIDR(%q) = %v, se esperaba %v", c.in, got, c.want)
		}
	}
}

func TestExpandCIDRErrors(t *testing.T) {
	for _, in := range []string{"no-cidr", "10.0.0.0/8", "2001:db8::/64"} {
		if _, err := expandCIDR(in); err == nil {
			t.Errorf("expandCIDR(%q) debería devolver error", in)
		}
	}
}

func TestExpandHosts(t *testing.T) {
	got, err := expandHosts("10.0.0.1, 10.0.0.1 ,192.168.0.0/30")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	want := []string{"10.0.0.1", "192.168.0.1", "192.168.0.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expandHosts = %v, se esperaba %v", got, want)
	}
}

func TestSanitize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"  hola  ", "hola"},
		{"linea1\r\nlinea2", "linea1"},
		{"a\x00b\x07c", "abc"},
		{"", ""},
	}
	for _, c := range cases {
		if got := sanitize(c.in); got != c.want {
			t.Errorf("sanitize(%q) = %q, se esperaba %q", c.in, got, c.want)
		}
	}
	long := strings.Repeat("x", 200)
	got := sanitize(long)
	if !strings.HasSuffix(got, "…") || len([]rune(got)) != 81 {
		t.Errorf("sanitize de cadena larga = %d runas, se esperaba 81 con '…'", len([]rune(got)))
	}
}

func TestTopPortsN(t *testing.T) {
	if got := topPortsN(3); !reflect.DeepEqual(got, []int{80, 23, 443}) {
		t.Errorf("topPortsN(3) = %v", got)
	}
	if got := topPortsN(0); len(got) != 0 {
		t.Errorf("topPortsN(0) = %v, se esperaba vacío", got)
	}
	if got := topPortsN(99999); len(got) != len(topPorts) {
		t.Errorf("topPortsN(99999) = %d, se esperaba %d", len(got), len(topPorts))
	}
}

func TestServiceName(t *testing.T) {
	if serviceName(22) != "ssh" {
		t.Errorf("serviceName(22) = %q, se esperaba ssh", serviceName(22))
	}
	if serviceName(65000) != "" {
		t.Errorf("serviceName(65000) debería ser vacío")
	}
}

func TestIsHTTPPort(t *testing.T) {
	if !isHTTPPort(80) || !isHTTPPort(8443) {
		t.Error("80 y 8443 deberían ser puertos HTTP(S)")
	}
	if isHTTPPort(22) {
		t.Error("22 no debería ser puerto HTTP")
	}
}

func TestParseProxy(t *testing.T) {
	cases := []struct {
		in               string
		addr, user, pass string
	}{
		{"127.0.0.1:1080", "127.0.0.1:1080", "", ""},
		{"socks5://127.0.0.1:1080", "127.0.0.1:1080", "", ""},
		{"user:pass@10.0.0.1:9050", "10.0.0.1:9050", "user", "pass"},
		{"socks5://bob@proxy.local:1080", "proxy.local:1080", "bob", ""},
	}
	for _, c := range cases {
		p, err := parseProxy(c.in)
		if err != nil {
			t.Errorf("parseProxy(%q) error inesperado: %v", c.in, err)
			continue
		}
		if p.addr != c.addr || p.user != c.user || p.pass != c.pass {
			t.Errorf("parseProxy(%q) = {%q,%q,%q}, se esperaba {%q,%q,%q}",
				c.in, p.addr, p.user, p.pass, c.addr, c.user, c.pass)
		}
	}
	for _, in := range []string{"sinpuerto", "user@", ""} {
		if _, err := parseProxy(in); err == nil {
			t.Errorf("parseProxy(%q) debería devolver error", in)
		}
	}
}

func TestGroupByHost(t *testing.T) {
	found := []Result{
		{Host: "10.0.0.2", Port: 22},
		{Host: "10.0.0.1", Port: 443},
		{Host: "10.0.0.1", Port: 80},
	}
	order, byHost := groupByHost(found)
	if !reflect.DeepEqual(order, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Errorf("orden = %v", order)
	}
	if len(byHost["10.0.0.1"]) != 2 || len(byHost["10.0.0.2"]) != 1 {
		t.Errorf("agrupación incorrecta: %v", byHost)
	}
}

func TestReadConfig(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/scan.conf"
	content := "# comentario\n; otro comentario\n\ntop = 100\ntimeout = 800ms\nsV = true\nrange = \"1-1000\"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	kv, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig error: %v", err)
	}
	want := map[string]string{"top": "100", "timeout": "800ms", "sV": "true", "range": "1-1000"}
	if !reflect.DeepEqual(kv, want) {
		t.Errorf("readConfig = %v, se esperaba %v", kv, want)
	}

	// Línea inválida (sin '=').
	bad := dir + "/bad.conf"
	os.WriteFile(bad, []byte("esto no es valido\n"), 0o644)
	if _, err := readConfig(bad); err == nil {
		t.Error("readConfig debería fallar con una línea sin '='")
	}
}

func TestGenCompletion(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		out, err := genCompletion(shell)
		if err != nil {
			t.Errorf("genCompletion(%q) error: %v", shell, err)
		}
		if !strings.Contains(out, "host") || len(out) == 0 {
			t.Errorf("genCompletion(%q) no contiene los flags esperados", shell)
		}
	}
	if _, err := genCompletion("tcsh"); err == nil {
		t.Error("genCompletion(\"tcsh\") debería devolver error")
	}
}

func TestProfilesExist(t *testing.T) {
	for _, name := range []string{"fast", "full", "stealth", "web"} {
		if _, ok := profiles[name]; !ok {
			t.Errorf("falta el perfil %q", name)
		}
	}
}

func TestDetectVersionRules(t *testing.T) {
	// Verifica que las reglas de versión extraen el producto esperado del banner.
	cases := []struct{ banner, want string }{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu", "OpenSSH 9.6p1"},
		{"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n", "nginx/1.25.3"},
	}
	for _, c := range cases {
		got := ""
		for _, rule := range versionRules {
			if m := rule.re.FindStringSubmatch(c.banner); m != nil {
				got = rule.tmpl
				for i := len(m) - 1; i >= 1; i-- {
					got = strings.ReplaceAll(got, "$"+strconv.Itoa(i), strings.TrimSpace(m[i]))
				}
				break
			}
		}
		if got != c.want {
			t.Errorf("banner %q → %q, se esperaba %q", c.banner, got, c.want)
		}
	}
}
