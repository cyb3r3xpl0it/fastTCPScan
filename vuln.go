package main

import "regexp"

// vulnRule asocia un patrón de servicio/versión/banner con una pista de vulnerabilidad.
// Es una heurística orientativa, NO un escáner de vulnerabilidades real.
type vulnRule struct {
	re   *regexp.Regexp
	note string
}

var vulnRules = []vulnRule{
	{regexp.MustCompile(`(?i)vsftpd\s*2\.3\.4`), "vsftpd 2.3.4: backdoor (CVE-2011-2523)"},
	{regexp.MustCompile(`(?i)ProFTPD\s*1\.3\.(3[a-c]|5)`), "ProFTPD: ejecución remota conocida (CVE-2015-3306 / 2010-4221)"},
	{regexp.MustCompile(`(?i)OpenSSH[_ ]([0-6]\.|7\.[0-1])`), "OpenSSH < 7.2: versión antigua con múltiples CVE, actualiza"},
	{regexp.MustCompile(`(?i)Apache[/ ]2\.4\.(49|50)`), "Apache 2.4.49/2.4.50: path traversal/RCE (CVE-2021-41773 / 2021-42013)"},
	{regexp.MustCompile(`(?i)Apache[/ ]2\.2\.`), "Apache 2.2.x: fin de soporte, múltiples CVE"},
	{regexp.MustCompile(`(?i)nginx[/ ]1\.(\d|1[0-9])\.`), "nginx < 1.20: revisa CVE de versiones antiguas"},
	{regexp.MustCompile(`(?i)Exim\s*4\.([89]\d)`), "Exim 4.8x/4.9x: revisa CVE-2019-10149 (RCE)"},
	{regexp.MustCompile(`(?i)Microsoft-IIS/[1-7]\.`), "IIS <= 7.x: versión muy antigua, fin de soporte"},
	{regexp.MustCompile(`(?i)OpenSSL/1\.0\.1`), "OpenSSL 1.0.1: vulnerable a Heartbleed (CVE-2014-0160)"},
	{regexp.MustCompile(`(?i)mod_ssl/2\.2`), "mod_ssl 2.2.x: pila antigua, revisa CVE"},
	{regexp.MustCompile(`(?i)PHP/5\.`), "PHP 5.x: fin de soporte, múltiples CVE"},
	{regexp.MustCompile(`(?i)Samba\s*3\.`), "Samba 3.x: revisa CVE-2017-7494 (SambaCry)"},
}

// checkVulns devuelve las pistas heurísticas que casan con el servicio/versión/banner.
func checkVulns(r Result) []string {
	subjects := []string{r.Version, r.Banner}
	if r.HTTP != nil {
		subjects = append(subjects, r.HTTP.Server)
	}
	if r.TLS != nil {
		if r.TLS.Expired {
			subjects = append(subjects, "") // marcador, ver abajo
		}
	}

	var hits []string
	seen := map[string]bool{}
	for _, rule := range vulnRules {
		for _, s := range subjects {
			if s == "" {
				continue
			}
			if rule.re.MatchString(s) && !seen[rule.note] {
				seen[rule.note] = true
				hits = append(hits, rule.note)
			}
		}
	}

	// Avisos derivados del estado TLS.
	if r.TLS != nil {
		if r.TLS.Expired {
			hits = append(hits, "Certificado TLS caducado o aún no válido")
		} else if r.TLS.DaysLeft >= 0 && r.TLS.DaysLeft <= 14 {
			hits = append(hits, "Certificado TLS caduca en menos de 15 días")
		}
		if r.TLS.SelfSigned {
			hits = append(hits, "Certificado TLS autofirmado")
		}
		switch r.TLS.Version {
		case "TLS 1.0", "TLS 1.1":
			hits = append(hits, "Versión TLS obsoleta ("+r.TLS.Version+")")
		}
	}
	return hits
}
