package main

import (
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"net"
	"sort"
)

// groupByHost agrupa los resultados por host conservando un orden estable.
func groupByHost(found []Result) ([]string, map[string][]Result) {
	order := []string{}
	byHost := map[string][]Result{}
	for _, r := range found {
		if _, ok := byHost[r.Host]; !ok {
			order = append(order, r.Host)
		}
		byHost[r.Host] = append(byHost[r.Host], r)
	}
	sort.Strings(order)
	return order, byHost
}

// --- XML compatible con Nmap (esquema nmaprun) ---

type nmapState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr,omitempty"`
}

type nmapService struct {
	Name    string `xml:"name,attr,omitempty"`
	Product string `xml:"product,attr,omitempty"`
	Method  string `xml:"method,attr"`
	Conf    int    `xml:"conf,attr"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Address   nmapAddress    `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname,omitempty"`
	Ports     []nmapPort     `xml:"ports>port"`
}

type nmapRun struct {
	XMLName          xml.Name   `xml:"nmaprun"`
	Scanner          string     `xml:"scanner,attr"`
	Args             string     `xml:"args,attr"`
	XMLOutputVersion string     `xml:"xmloutputversion,attr"`
	Hosts            []nmapHost `xml:"host"`
}

func addrType(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "ipv6"
	}
	return "ipv4"
}

func writeXML(w io.Writer, found []Result) error {
	order, byHost := groupByHost(found)

	method := "table"
	if *sv {
		method = "probed"
	}

	run := nmapRun{
		Scanner:          "fastTCPScan",
		Args:             "fastTCPScan",
		XMLOutputVersion: "1.05",
	}

	for _, h := range order {
		host := nmapHost{}
		host.Status.State = "up"
		host.Address = nmapAddress{Addr: h, AddrType: addrType(h)}

		for _, r := range byHost[h] {
			if r.RDNS != "" && len(host.Hostnames) == 0 {
				host.Hostnames = append(host.Hostnames, nmapHostname{Name: r.RDNS, Type: "PTR"})
			}
			product := r.Version
			if product == "" {
				product = r.Banner
			}
			host.Ports = append(host.Ports, nmapPort{
				Protocol: r.Proto,
				PortID:   r.Port,
				State:    nmapState{State: r.State, Reason: "response"},
				Service:  nmapService{Name: r.Service, Product: product, Method: method, Conf: 10},
			})
		}
		run.Hosts = append(run.Hosts, host)
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "<!DOCTYPE nmaprun>\n"); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(run); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// --- HTML ---

var htmlTmpl = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>FastTCPScan — Reporte</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #222; }
  h1 { color: #056; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }
  th, td { border: 1px solid #ccc; padding: .4rem .6rem; text-align: left; font-size: .85rem; vertical-align: top; }
  th { background: #056; color: #fff; }
  tr:nth-child(even) { background: #f4f7f8; }
  .open { color: #197a19; font-weight: bold; }
  .host { margin-top: 1.5rem; }
  .vuln { color: #b00; }
  code { background: #eef; padding: 0 .3rem; }
  small { color: #666; }
</style>
</head>
<body>
<h1>FastTCPScan — Reporte</h1>
{{range .}}
<div class="host">
  <h2>{{.Host}}{{if .RDNS}} <small>({{.RDNS}})</small>{{end}}</h2>
  <table>
    <thead><tr><th>Puerto</th><th>Proto</th><th>Estado</th><th>Servicio</th><th>Versión</th><th>Detalles</th></tr></thead>
    <tbody>
    {{range .Ports}}
      <tr>
        <td><code>{{.Port}}</code></td>
        <td>{{.Proto}}</td>
        <td class="open">{{.State}}</td>
        <td>{{.Service}}</td>
        <td>{{.Version}}</td>
        <td>
          {{if .HTTP}}{{with .HTTP}}{{if .Status}}{{.Status}}<br>{{end}}{{if .Title}}<b>{{.Title}}</b><br>{{end}}{{if .Server}}Server: {{.Server}}<br>{{end}}{{if .Location}}→ {{.Location}}<br>{{end}}{{end}}{{end}}
          {{if .TLS}}{{with .TLS}}TLS {{.Version}} · {{.Subject}} · caduca {{.Expires}} ({{.DaysLeft}}d){{if .SelfSigned}} · autofirmado{{end}}{{if .Expired}} · CADUCADO{{end}}<br>{{end}}{{end}}
          {{if .Banner}}<small>{{.Banner}}</small><br>{{end}}
          {{range .Vulns}}<span class="vuln">⚠ {{.}}</span><br>{{end}}
        </td>
      </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{else}}
<p>No se encontraron puertos.</p>
{{end}}
<footer><small>Generado por FastTCPScan</small></footer>
</body>
</html>
`))

// htmlHost agrupa los puertos de un host para la plantilla HTML.
type htmlHost struct {
	Host  string
	RDNS  string
	Ports []Result
}

func writeHTML(w io.Writer, found []Result) error {
	order, byHost := groupByHost(found)
	var hosts []htmlHost
	for _, h := range order {
		hh := htmlHost{Host: h, Ports: byHost[h]}
		for _, r := range byHost[h] {
			if r.RDNS != "" {
				hh.RDNS = r.RDNS
				break
			}
		}
		hosts = append(hosts, hh)
	}
	if err := htmlTmpl.Execute(w, hosts); err != nil {
		return fmt.Errorf("error generando HTML: %v", err)
	}
	return nil
}
