package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"
)

func allFlagNames() []string {
	var names []string
	flag.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	sort.Strings(names)
	return names
}

// genCompletion devuelve el script de autocompletado para la shell indicada.
func genCompletion(shell string) (string, error) {
	names := allFlagNames()

	switch shell {
	case "bash":
		dashed := make([]string, len(names))
		for i, n := range names {
			dashed[i] = "-" + n
		}
		return fmt.Sprintf(`# Autocompletado bash para fastTCPScan.
# Instalar: fastTCPScan -completion bash > /etc/bash_completion.d/fastTCPScan
_fastTCPScan() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local flags="%s"
  COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )
  return 0
}
complete -F _fastTCPScan fastTCPScan
`, strings.Join(dashed, " ")), nil

	case "zsh":
		var b strings.Builder
		b.WriteString("#compdef fastTCPScan\n")
		b.WriteString("# Instalar: fastTCPScan -completion zsh > \"${fpath[1]}/_fastTCPScan\"\n")
		b.WriteString("_arguments \\\n")
		for i, n := range names {
			desc := sanitizeDesc(flag.Lookup(n).Usage)
			end := " \\\n"
			if i == len(names)-1 {
				end = "\n"
			}
			b.WriteString(fmt.Sprintf("  '-%s[%s]'%s", n, desc, end))
		}
		return b.String(), nil

	case "fish":
		var b strings.Builder
		b.WriteString("# Autocompletado fish para fastTCPScan.\n")
		b.WriteString("# Instalar: fastTCPScan -completion fish > ~/.config/fish/completions/fastTCPScan.fish\n")
		for _, n := range names {
			desc := sanitizeDesc(flag.Lookup(n).Usage)
			b.WriteString(fmt.Sprintf("complete -c fastTCPScan -o %s -d '%s'\n", n, desc))
		}
		return b.String(), nil

	default:
		return "", fmt.Errorf("shell no soportada: %q (usa bash, zsh o fish)", shell)
	}
}

// sanitizeDesc limpia la descripción de un flag para incrustarla en el script.
func sanitizeDesc(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.ReplaceAll(s, "'", "")
	s = strings.ReplaceAll(s, "[", "(")
	s = strings.ReplaceAll(s, "]", ")")
	return s
}
