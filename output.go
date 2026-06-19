package main

import (
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"sort"
)

// --- XML (estilo Nmap) ---

type xmlState struct {
	State string `xml:"state,attr"`
}

type xmlService struct {
	Name    string `xml:"name,attr,omitempty"`
	Version string `xml:"version,attr,omitempty"`
	Banner  string `xml:"banner,attr,omitempty"`
}

type xmlPort struct {
	Protocol string     `xml:"protocol,attr"`
	PortID   int        `xml:"portid,attr"`
	State    xmlState   `xml:"state"`
	Service  xmlService `xml:"service"`
}

type xmlHost struct {
	Addr  string    `xml:"addr,attr"`
	RDNS  string    `xml:"rdns,attr,omitempty"`
	Ports []xmlPort `xml:"ports>port"`
}

type xmlRun struct {
	XMLName xml.Name  `xml:"scanresults"`
	Hosts   []xmlHost `xml:"host"`
}

// groupByHost agrupa los resultados por host conservando el orden.
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

func writeXML(w io.Writer, found []Result) error {
	order, byHost := groupByHost(found)
	run := xmlRun{}
	for _, h := range order {
		xh := xmlHost{Addr: h}
		for _, r := range byHost[h] {
			if r.RDNS != "" {
				xh.RDNS = r.RDNS
			}
			xh.Ports = append(xh.Ports, xmlPort{
				Protocol: r.Proto,
				PortID:   r.Port,
				State:    xmlState{State: r.State},
				Service:  xmlService{Name: r.Service, Version: r.Version, Banner: r.Banner},
			})
		}
		run.Hosts = append(run.Hosts, xh)
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
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
  th, td { border: 1px solid #ccc; padding: .4rem .6rem; text-align: left; font-size: .9rem; }
  th { background: #056; color: #fff; }
  tr:nth-child(even) { background: #f4f7f8; }
  .open { color: #197a19; font-weight: bold; }
  .host { margin-top: 1.5rem; }
  code { background: #eef; padding: 0 .3rem; }
</style>
</head>
<body>
<h1>FastTCPScan — Reporte</h1>
{{range .Hosts}}
<div class="host">
  <h2>{{.Addr}}{{if .RDNS}} <small>({{.RDNS}})</small>{{end}}</h2>
  <table>
    <thead><tr><th>Puerto</th><th>Proto</th><th>Estado</th><th>Servicio</th><th>Versión</th><th>Banner</th></tr></thead>
    <tbody>
    {{range .Ports}}
      <tr>
        <td><code>{{.PortID}}</code></td>
        <td>{{.Protocol}}</td>
        <td class="open">{{.State.State}}</td>
        <td>{{.Service.Name}}</td>
        <td>{{.Service.Version}}</td>
        <td>{{.Service.Banner}}</td>
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

func writeHTML(w io.Writer, found []Result) error {
	order, byHost := groupByHost(found)
	run := xmlRun{}
	for _, h := range order {
		xh := xmlHost{Addr: h}
		for _, r := range byHost[h] {
			if r.RDNS != "" {
				xh.RDNS = r.RDNS
			}
			xh.Ports = append(xh.Ports, xmlPort{
				Protocol: r.Proto,
				PortID:   r.Port,
				State:    xmlState{State: r.State},
				Service:  xmlService{Name: r.Service, Version: r.Version, Banner: r.Banner},
			})
		}
		run.Hosts = append(run.Hosts, xh)
	}
	if err := htmlTmpl.Execute(w, run); err != nil {
		return fmt.Errorf("error generando HTML: %v", err)
	}
	return nil
}
