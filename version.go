package main

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// versionRule asocia un patrón en el banner con una plantilla de versión ($1, $2…).
type versionRule struct {
	re   *regexp.Regexp
	tmpl string
}

// versionRules son heurísticas para identificar producto y versión a partir del banner.
var versionRules = []versionRule{
	{regexp.MustCompile(`(?i)SSH-[\d.]+-OpenSSH[_-]?([\w.\-p]+)`), "OpenSSH $1"},
	{regexp.MustCompile(`(?i)SSH-[\d.]+-([\w.\-]+)`), "SSH $1"},
	{regexp.MustCompile(`(?i)220[- ].*?ProFTPD\s+([\d.]+)`), "ProFTPD $1"},
	{regexp.MustCompile(`(?i)220[- ].*?vsftpd\s+([\d.]+)`), "vsftpd $1"},
	{regexp.MustCompile(`(?i)220[- ].*?FileZilla\s+Server[^\d]*([\d.]+)`), "FileZilla Server $1"},
	{regexp.MustCompile(`(?i)220[- ].*?Exim\s+([\d.]+)`), "Exim $1"},
	{regexp.MustCompile(`(?i)220[- ].*?Postfix`), "Postfix SMTP"},
	{regexp.MustCompile(`(?i)220[- ].*?Microsoft ESMTP`), "Microsoft ESMTP"},
	{regexp.MustCompile(`(?i)Server:\s*([^\r\n]+)`), "$1"},
	{regexp.MustCompile(`(?i)\+OK\s+([^\r\n]*POP3[^\r\n]*)`), "$1"},
	{regexp.MustCompile(`(?i)\* OK\s+([^\r\n]*IMAP[^\r\n]*)`), "$1"},
	{regexp.MustCompile(`(?i)Redis[^\r\n]*?version[:= ]+([\d.]+)`), "Redis $1"},
}

// detectVersion lee la respuesta del servicio y extrae producto/versión si puede.
func detectVersion(conn net.Conn, port int) (version, banner string) {
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	n, err := conn.Read(buf)

	// Servicios que no saludan primero (HTTP, etc.): enviamos una petición.
	if (err != nil || n == 0) && isHTTPPort(port) {
		conn.SetWriteDeadline(time.Now().Add(750 * time.Millisecond))
		conn.Write([]byte("GET / HTTP/1.0\r\nHost: scan\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err = conn.Read(buf)
	}
	if err != nil || n == 0 {
		return "", ""
	}

	raw := string(buf[:n])
	banner = sanitize(raw)

	for _, rule := range versionRules {
		m := rule.re.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		v := rule.tmpl
		for i := len(m) - 1; i >= 1; i-- {
			v = strings.ReplaceAll(v, "$"+strconv.Itoa(i), strings.TrimSpace(m[i]))
		}
		return sanitize(v), banner
	}
	return "", banner
}
