package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	host    = flag.String("host", "127.0.0.1", "Host, IP, CIDR o lista separada por comas (ej. 192.168.1.0/24,10.0.0.1)")
	portsF  = flag.String("range", "1-65535", "Puertos a comprobar: 80,443,1-65535,1000-2000, ...")
	threads = flag.Int("threads", 1000, "Número de workers concurrentes")
	timeout = flag.Duration("timeout", time.Second, "Timeout por puerto (ej. 500ms, 2s)")
	retries = flag.Int("retries", 0, "Reintentos por puerto antes de marcarlo como cerrado")
	proto   = flag.String("proto", "tcp", "Protocolo: tcp o udp")
	banner  = flag.Bool("banner", false, "Intentar capturar el banner del servicio en puertos abiertos")
	jsonOut = flag.Bool("json", false, "Salida en formato JSON")
	showAll = flag.Bool("all", false, "Mostrar también puertos cerrados/filtrados")

	topN      = flag.Int("top", 0, "Escanear solo los N puertos más comunes (ignora -range)")
	inFile    = flag.String("iL", "", "Leer objetivos (host/IP/CIDR) desde archivo, uno por línea")
	outFile   = flag.String("o", "", "Guardar los resultados en un archivo (en lugar de stdout)")
	rate      = flag.Int("rate", 0, "Límite de sondas por segundo (0 = sin límite)")
	discover  = flag.Bool("discover", false, "Descubrir hosts vivos (TCP ping) y omitir los que no respondan")
	randomize = flag.Bool("randomize", false, "Aleatorizar el orden de hosts y puertos")

	format   = flag.String("format", "text", "Formato de salida: text, json, csv o grep")
	noColor  = flag.Bool("no-color", false, "Desactivar el color en la salida de texto")
	tlsInfo  = flag.Bool("tls", false, "Realizar handshake TLS en puertos abiertos y mostrar datos del certificado")
	verbose  = flag.Bool("v", false, "Salida detallada (verbose)")
	quiet    = flag.Bool("q", false, "Salida mínima: solo resultados, sin progreso ni resumen")
	deadline = flag.Duration("deadline", 0, "Tiempo máximo total del escaneo (ej. 5m); 0 = sin límite")
)

// limiter regula el ritmo de sondas cuando -rate > 0 (nil = sin límite).
var limiter <-chan time.Time

// gate limita las sondas concurrentes y se reduce ante errores de "too many open files".
var gate *adaptiveGate

// verbosity: 0 = silencioso, 1 = normal, 2 = detallado.
var verbosity = 1

// useColor indica si se debe colorear la salida de texto.
var useColor bool

// Códigos ANSI para colorear estados.
const (
	cReset  = "\033[0m"
	cGreen  = "\033[32m"
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cBold   = "\033[1m"
)

// topPorts son los puertos TCP más comunes, ordenados por frecuencia de uso.
var topPorts = []int{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
	1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81,
	6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433,
	49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153,
	8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357,
	427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
	7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028,
	873, 1755, 2717, 4899, 9100, 119, 37, 6379, 27017, 9200, 11211, 9090, 5601,
}

// topPortsN devuelve los primeros n puertos de la lista de más comunes.
func topPortsN(n int) []int {
	if n > len(topPorts) {
		n = len(topPorts)
	}
	out := make([]int, n)
	copy(out, topPorts[:n])
	return out
}

// Result describe el estado de un puerto en un host concreto.
type Result struct {
	Host    string   `json:"host"`
	Port    int      `json:"port"`
	Proto   string   `json:"proto"`
	State   string   `json:"state"`
	Service string   `json:"service,omitempty"`
	Banner  string   `json:"banner,omitempty"`
	TLS     *TLSInfo `json:"tls,omitempty"`
}

// TLSInfo resume el certificado presentado por un servicio TLS.
type TLSInfo struct {
	Subject  string   `json:"subject,omitempty"`
	Issuer   string   `json:"issuer,omitempty"`
	Expires  string   `json:"expires,omitempty"`
	DNSNames []string `json:"dns_names,omitempty"`
}

// adaptiveGate limita las sondas en vuelo y puede reducir su límite dinámicamente.
type adaptiveGate struct {
	mu       sync.Mutex
	cond     *sync.Cond
	limit    int
	inflight int
	floor    int
}

func newGate(limit int) *adaptiveGate {
	floor := 50
	if limit < floor {
		floor = limit
	}
	g := &adaptiveGate{limit: limit, floor: floor}
	g.cond = sync.NewCond(&g.mu)
	return g
}

func (g *adaptiveGate) acquire() {
	g.mu.Lock()
	for g.inflight >= g.limit {
		g.cond.Wait()
	}
	g.inflight++
	g.mu.Unlock()
}

func (g *adaptiveGate) release() {
	g.mu.Lock()
	g.inflight--
	g.cond.Signal()
	g.mu.Unlock()
}

// shrink reduce el límite un 25% (con suelo) tras un error de descriptores agotados.
func (g *adaptiveGate) shrink() {
	g.mu.Lock()
	if g.limit > g.floor {
		g.limit = g.limit * 3 / 4
		if g.limit < g.floor {
			g.limit = g.floor
		}
		if verbosity >= 2 {
			fmt.Fprintf(os.Stderr, "[v] Descriptores agotados: reduciendo concurrencia a %d\n", g.limit)
		}
	}
	g.mu.Unlock()
}

// job es una unidad de trabajo: un host y un puerto a sondear.
type job struct {
	host string
	port int
}

// services mapea los puertos más comunes a su servicio asociado.
var services = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
	123: "ntp", 135: "msrpc", 137: "netbios", 138: "netbios", 139: "netbios",
	143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
	514: "syslog", 587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
	995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
	2049: "nfs", 2082: "cpanel", 2083: "cpanel", 3000: "http-alt", 3128: "squid",
	3306: "mysql", 3389: "rdp", 5060: "sip", 5432: "postgresql", 5601: "kibana",
	5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm", 6379: "redis",
	6443: "kubernetes", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
	8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
	9090: "prometheus", 9200: "elasticsearch", 9300: "elasticsearch",
	11211: "memcached", 27017: "mongodb",
}

func serviceName(p int) string { return services[p] }

func isHTTPPort(p int) bool {
	switch p {
	case 80, 443, 3000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090:
		return true
	}
	return false
}

func fatalf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", a...)
	os.Exit(1)
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// expandPorts convierte "80,443,1000-2000" en una lista ordenada y sin duplicados.
func expandPorts(r string) ([]int, error) {
	seen := make(map[int]bool)
	var ports []int

	for _, block := range strings.Split(r, ",") {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}

		rg := strings.Split(block, "-")
		lo, err := strconv.Atoi(strings.TrimSpace(rg[0]))
		if err != nil {
			return nil, fmt.Errorf("rango de puertos inválido: %q", block)
		}

		hi := lo
		if len(rg) > 1 {
			hi, err = strconv.Atoi(strings.TrimSpace(rg[1]))
			if err != nil {
				return nil, fmt.Errorf("rango de puertos inválido: %q", block)
			}
		}
		if lo > hi {
			lo, hi = hi, lo
		}

		for p := lo; p <= hi; p++ {
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("puerto fuera de rango (1-65535): %d", p)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no se especificaron puertos")
	}
	return ports, nil
}

// expandHosts acepta IPs, hostnames, CIDR y listas separadas por comas.
func expandHosts(arg string) ([]string, error) {
	var hosts []string
	seen := make(map[string]bool)

	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}

	for _, part := range strings.Split(arg, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			ips, err := expandCIDR(part)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				add(ip)
			}
		} else {
			add(part)
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no se especificaron hosts")
	}
	return hosts, nil
}

// flagSet indica si el usuario pasó explícitamente un flag por línea de comandos.
func flagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// gatherHosts combina los objetivos de -host (si se indicó) y del archivo -iL.
func gatherHosts() ([]string, error) {
	var sources []string

	// Solo usamos -host si el usuario lo pasó o si no hay archivo (evita el default 127.0.0.1).
	if *inFile == "" || flagSet("host") {
		sources = append(sources, *host)
	}

	if *inFile != "" {
		lines, err := readTargetsFile(*inFile)
		if err != nil {
			return nil, err
		}
		sources = append(sources, lines...)
	}

	return expandHosts(strings.Join(sources, ","))
}

// readTargetsFile lee objetivos de un archivo (uno por línea, ignora vacías y #comentarios).
func readTargetsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir %q: %v", path, err)
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error leyendo %q: %v", path, err)
	}
	return lines, nil
}

// discoverPorts son los puertos usados para el "TCP ping" de descubrimiento de hosts.
var discoverPorts = []int{80, 443, 22, 3389, 8080, 445, 21, 25}

// discoverHosts devuelve solo los hosts que responden en algún puerto común.
func discoverHosts(ctx context.Context, hosts []string) []string {
	type item struct {
		host  string
		alive bool
	}

	in := make(chan string)
	out := make(chan item)
	done := ctx.Done()

	n := *threads
	if n > len(hosts) {
		n = len(hosts)
	}
	if n < 1 {
		n = 1
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			for h := range in {
				out <- item{h, hostAlive(ctx, h)}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, h := range hosts {
			select {
			case in <- h:
			case <-done:
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	var alive []string
	for it := range out {
		if it.alive {
			alive = append(alive, it.host)
		}
	}
	sort.Strings(alive)
	return alive
}

// hostAlive intenta conectar a varios puertos comunes; devuelve true al primer éxito.
func hostAlive(ctx context.Context, h string) bool {
	dialer := net.Dialer{Timeout: *timeout}
	for _, p := range discoverPorts {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(h, strconv.Itoa(p)))
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// shuffleInts baraja una copia de la lista de puertos.
func shuffleInts(s []int) {
	rand.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}

// shuffleStrings baraja una lista de hosts en sitio.
func shuffleStrings(s []string) {
	rand.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("CIDR inválido: %q", cidr)
	}

	// Evitamos enumerar rangos enormes (p. ej. una /64 de IPv6 son 2^64 direcciones).
	if ones, bits := ipnet.Mask.Size(); bits-ones > 20 {
		return nil, fmt.Errorf("rango CIDR demasiado grande (%s): usa un prefijo más específico (≤ ~1M direcciones)", cidr)
	}

	var ips []string
	ip := dupIP(ipnet.IP)
	for ; ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Descartamos red y broadcast en subredes mayores que /31.
	if ones, bits := ipnet.Mask.Size(); bits-ones > 1 && len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func dupIP(ip net.IP) net.IP {
	d := make(net.IP, len(ip))
	copy(d, ip)
	return d
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// generateJobs emite cada combinación host×puerto, respetando la cancelación.
func generateJobs(ctx context.Context, hosts []string, ports []int) <-chan job {
	out := make(chan job)
	done := ctx.Done()

	go func() {
		defer close(out)
		for _, h := range hosts {
			for _, p := range ports {
				select {
				case out <- job{h, p}:
				case <-done:
					return
				}
			}
		}
	}()
	return out
}

// scan reparte los jobs entre los workers y devuelve un canal de resultados.
func scan(ctx context.Context, jobs <-chan job) <-chan Result {
	out := make(chan Result)
	done := ctx.Done()

	n := *threads
	if n < 1 {
		n = 1
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case j, ok := <-jobs:
					if !ok {
						return
					}
					// Respetamos el límite de sondas por segundo si está activo.
					if limiter != nil {
						select {
						case <-limiter:
						case <-done:
							return
						}
					}
					// Concurrencia adaptativa: esperamos un hueco libre.
					gate.acquire()
					r := probe(ctx, j)
					gate.release()
					select {
					case out <- r:
					case <-done:
						return
					}
				case <-done:
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// probe sondea un único puerto, con reintentos y detección de servicio/banner.
func probe(ctx context.Context, j job) Result {
	res := Result{Host: j.host, Port: j.port, Proto: *proto, State: "closed"}
	addr := net.JoinHostPort(j.host, strconv.Itoa(j.port))

	var (
		conn net.Conn
		err  error
	)
	dialer := net.Dialer{Timeout: *timeout}

	for attempt := 0; attempt <= *retries; attempt++ {
		select {
		case <-ctx.Done():
			return res
		default:
		}
		conn, err = dialer.DialContext(ctx, *proto, addr)
		if err == nil {
			break
		}
		// Si agotamos descriptores de archivo, reducimos la concurrencia.
		if gate != nil && isTooManyFiles(err) {
			gate.shrink()
		}
	}
	if err != nil {
		return res
	}
	defer conn.Close()

	res.Service = serviceName(j.port)

	// UDP no tiene conexión: enviamos una sonda y deducimos el estado.
	if *proto == "udp" {
		conn.SetDeadline(time.Now().Add(*timeout))
		conn.Write([]byte{0x00})

		buf := make([]byte, 1024)
		n, rerr := conn.Read(buf)
		switch {
		case rerr == nil:
			res.State = "open"
			res.Banner = sanitize(string(buf[:n]))
		case isTimeout(rerr):
			res.State = "open|filtered"
		default:
			res.State = "closed"
		}
		return res
	}

	res.State = "open"
	if *banner {
		res.Banner = grabBanner(conn, j.port)
	}
	if *tlsInfo {
		res.TLS = grabTLS(ctx, j.host, j.port)
	}
	return res
}

// grabTLS realiza un handshake TLS y extrae los datos básicos del certificado.
func grabTLS(ctx context.Context, host string, port int) *TLSInfo {
	raw, err := (&net.Dialer{Timeout: *timeout}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(*timeout))

	cfg := &tls.Config{InsecureSkipVerify: true}
	if net.ParseIP(host) == nil { // SNI solo si es un nombre, no una IP
		cfg.ServerName = host
	}

	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		return nil
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	c := certs[0]
	return &TLSInfo{
		Subject:  c.Subject.CommonName,
		Issuer:   c.Issuer.CommonName,
		Expires:  c.NotAfter.Format("2006-01-02"),
		DNSNames: c.DNSNames,
	}
}

// grabBanner lee el saludo del servicio; para puertos web envía una petición HEAD.
func grabBanner(conn net.Conn, port int) string {
	buf := make([]byte, 1024)

	conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
	n, err := conn.Read(buf)

	if (err != nil || n == 0) && isHTTPPort(port) {
		conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
		n, err = conn.Read(buf)
	}

	if err != nil || n == 0 {
		return ""
	}
	return sanitize(string(buf[:n]))
}

// sanitize deja la primera línea imprimible del banner, acotada en longitud.
func sanitize(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, s)
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return strings.TrimSpace(s)
}

// isTerminal indica si el descriptor es una terminal interactiva.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// colorState devuelve el estado coloreado si el color está activo.
func colorState(state string) string {
	if !useColor {
		return state
	}
	switch {
	case strings.HasPrefix(state, "open|"):
		return cYellow + state + cReset
	case strings.HasPrefix(state, "open"):
		return cGreen + state + cReset
	default:
		return cRed + state + cReset
	}
}

// writeResults vuelca los resultados en el formato elegido.
func writeResults(w io.Writer, found []Result) error {
	switch *format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if found == nil {
			found = []Result{}
		}
		return enc.Encode(found)

	case "csv":
		cw := csv.NewWriter(w)
		cw.Write([]string{"host", "port", "proto", "state", "service", "banner", "tls_subject", "tls_expires"})
		for _, r := range found {
			subj, exp := "", ""
			if r.TLS != nil {
				subj, exp = r.TLS.Subject, r.TLS.Expires
			}
			cw.Write([]string{r.Host, strconv.Itoa(r.Port), r.Proto, r.State, r.Service, r.Banner, subj, exp})
		}
		cw.Flush()
		return cw.Error()

	case "grep":
		for _, r := range found {
			fmt.Fprintf(w, "%s:%d:%s:%s:%s\n", r.Host, r.Port, r.Proto, r.State, r.Service)
		}
		return nil

	default: // text
		for _, r := range found {
			line := fmt.Sprintf("%s:%-5d  %-13s", r.Host, r.Port, colorState(r.State))
			if r.Service != "" {
				line += " " + r.Service
			}
			if r.Banner != "" {
				line += "  | " + r.Banner
			}
			if r.TLS != nil {
				line += fmt.Sprintf("  | TLS CN=%s issuer=%s exp=%s", r.TLS.Subject, r.TLS.Issuer, r.TLS.Expires)
			}
			fmt.Fprintln(w, line)
		}
		return nil
	}
}

func main() {
	flag.Parse()

	*proto = strings.ToLower(strings.TrimSpace(*proto))
	if *proto != "tcp" && *proto != "udp" {
		fatalf("protocolo no soportado: %q (usa tcp o udp)", *proto)
	}
	if *topN < 0 {
		fatalf("-top no puede ser negativo")
	}
	if *rate < 0 {
		fatalf("-rate no puede ser negativo")
	}

	// -json es un alias de -format json (compatibilidad).
	*format = strings.ToLower(strings.TrimSpace(*format))
	if *jsonOut {
		*format = "json"
	}
	switch *format {
	case "text", "json", "csv", "grep":
	default:
		fatalf("formato no soportado: %q (usa text, json, csv o grep)", *format)
	}

	// Nivel de verbosidad.
	if *quiet && *verbose {
		fatalf("-q y -v son mutuamente excluyentes")
	}
	switch {
	case *quiet:
		verbosity = 0
	case *verbose:
		verbosity = 2
	default:
		verbosity = 1
	}

	checkFDLimit()

	hosts, err := gatherHosts()
	if err != nil {
		fatalf("%v", err)
	}

	var ports []int
	if *topN > 0 {
		ports = topPortsN(*topN)
	} else {
		ports, err = expandPorts(*portsF)
		if err != nil {
			fatalf("%v", err)
		}
	}

	if *randomize {
		shuffleStrings(hosts)
		shuffleInts(ports)
	}

	// Límite global de sondas por segundo.
	if *rate > 0 {
		limiter = time.Tick(time.Second / time.Duration(*rate))
	}

	gate = newGate(*threads)

	// Salida de resultados: archivo si se indicó -o, si no stdout.
	var sink io.Writer = os.Stdout
	sinkIsTTY := isTerminal(os.Stdout)
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fatalf("no se pudo crear %q: %v", *outFile, err)
		}
		defer f.Close()
		sink = f
		sinkIsTTY = false
	}
	useColor = !*noColor && *format == "text" && sinkIsTTY

	parent := context.Background()
	var ctx context.Context
	var cancel context.CancelFunc
	if *deadline > 0 {
		ctx, cancel = context.WithTimeout(parent, *deadline)
	} else {
		ctx, cancel = context.WithCancel(parent)
	}
	defer cancel()

	// Ctrl+C / SIGTERM cancelan el escaneo de forma limpia.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\n[!] Interrumpido, cerrando…")
		cancel()
	}()

	// Descubrimiento previo de hosts vivos (TCP ping).
	if *discover {
		if verbosity >= 1 {
			fmt.Fprintf(os.Stderr, "[*] Descubriendo hosts vivos entre %d objetivo(s)…\n", len(hosts))
		}
		hosts = discoverHosts(ctx, hosts)
		if verbosity >= 1 {
			fmt.Fprintf(os.Stderr, "[*] %d host(s) vivo(s)\n", len(hosts))
		}
		if verbosity >= 2 {
			for _, h := range hosts {
				fmt.Fprintf(os.Stderr, "[v]   vivo: %s\n", h)
			}
		}
		if len(hosts) == 0 {
			fmt.Fprintln(os.Stderr, "[!] Ningún host respondió; nada que escanear.")
			return
		}
	}

	total := int64(len(hosts) * len(ports))

	if verbosity >= 1 {
		fmt.Fprintf(os.Stderr, "\n[*] Escaneando %d host(s) × %d puerto(s) = %d sondas [%s]\n\n",
			len(hosts), len(ports), total, strings.ToUpper(*proto))
	}

	start := time.Now()
	results := scan(ctx, generateJobs(ctx, hosts, ports))

	var scanned, openCount int64
	var found []Result

	// Indicador de progreso a stderr (no contamina los resultados en stdout/archivo).
	progressDone := make(chan struct{})
	if verbosity >= 1 {
		go func() {
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-progressDone:
					return
				case <-ticker.C:
					done := atomic.LoadInt64(&scanned)
					fmt.Fprintf(os.Stderr, "\r[*] Progreso: %d/%d (%.1f%%) | abiertos: %d   ",
						done, total, float64(done)/float64(total)*100, atomic.LoadInt64(&openCount))
				}
			}
		}()
	}

	for r := range results {
		atomic.AddInt64(&scanned, 1)
		if strings.HasPrefix(r.State, "open") {
			atomic.AddInt64(&openCount, 1)
			found = append(found, r)
		} else if *showAll {
			found = append(found, r)
		}
	}
	close(progressDone)
	if verbosity >= 1 {
		fmt.Fprintf(os.Stderr, "\r%-70s\r", "") // limpiamos la línea de progreso
	}

	sort.Slice(found, func(i, j int) bool {
		if found[i].Host != found[j].Host {
			return found[i].Host < found[j].Host
		}
		return found[i].Port < found[j].Port
	})

	if err := writeResults(sink, found); err != nil {
		fatalf("no se pudieron escribir los resultados: %v", err)
	}

	if verbosity >= 1 {
		elapsed := time.Since(start).Round(time.Millisecond)
		open := atomic.LoadInt64(&openCount)
		if *outFile != "" {
			fmt.Fprintf(os.Stderr, "[*] Resultados guardados en %q\n", *outFile)
		}
		summary := fmt.Sprintf("\n[+] Completado en %s — %d abierto(s), %d sondas realizadas de %d en total\n",
			elapsed, open, scanned, total)
		if useColor || (!*noColor && isTerminal(os.Stderr)) {
			summary = cBold + summary + cReset
		}
		fmt.Fprint(os.Stderr, summary)
	}
}
