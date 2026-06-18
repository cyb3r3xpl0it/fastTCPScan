<h1 align="center">FastTCPScan</h1>

<p align="center">
  <img alt="Github top language" src="https://img.shields.io/github/languages/top/cyb3r3xpl0it/fastTCPScan?color=56BEB8">
  <img alt="Github language count" src="https://img.shields.io/github/languages/count/cyb3r3xpl0it/fastTCPScan?color=56BEB8">
  <img alt="Repository size" src="https://img.shields.io/github/repo-size/cyb3r3xpl0it/fastTCPScan?color=56BEB8">
  <img alt="License" src="https://img.shields.io/github/license/cyb3r3xpl0it/fastTCPScan?color=56BEB8">
</p>

<p align="center">
  <a href="#dart-about">About</a> &#xa0; | &#xa0; 
  <a href="#sparkles-features">Features</a> &#xa0; | &#xa0;
  <a href="#rocket-technologies">Technologies</a> &#xa0; | &#xa0;
  <a href="#white_check_mark-requirements">Requirements</a> &#xa0; | &#xa0;
  <a href="#checkered_flag-starting">Starting</a> &#xa0; | &#xa0;
  <a href="#wrench-usage">Usage</a> &#xa0; | &#xa0;
  <a href="#memo-license">License</a>
</p>

<br>

## :dart: About ##

FastTCPScan is a fast, concurrent TCP port scanner written in Go. It uses
goroutines and channels to scan large port ranges in parallel, making it
ideal for quickly discovering open ports on a host.

## :sparkles: Features ##

:heavy_check_mark: Highly concurrent scanning (configurable number of threads);\
:heavy_check_mark: Flexible port ranges (`80,443,1-65535,1000-2000, ...`) and top-ports preset (`-top N`);\
:heavy_check_mark: Multiple targets: single host, comma-separated lists, CIDR (`192.168.1.0/24`), IPv4 and IPv6;\
:heavy_check_mark: Read targets from a file (`-iL`) and save results to a file (`-o`);\
:heavy_check_mark: Host discovery (TCP ping) to skip dead hosts (`-discover`);\
:heavy_check_mark: Rate limiting (`-rate`) and randomized scan order (`-randomize`);\
:heavy_check_mark: TCP and UDP scanning;\
:heavy_check_mark: Service detection, optional banner grabbing and TLS certificate inspection (`-tls`);\
:heavy_check_mark: Configurable timeout and retries per port;\
:heavy_check_mark: Multiple output formats: `text`, `json`, `csv` and `grep`;\
:heavy_check_mark: Colored output (auto-disabled when piped) and verbosity levels (`-v` / `-q`);\
:heavy_check_mark: Global deadline (`-deadline`), file-descriptor auto-tuning and adaptive concurrency;\
:heavy_check_mark: Live progress indicator and clean Ctrl+C cancellation;\
:heavy_check_mark: Single static binary with no external dependencies.

## :rocket: Technologies ##

The following tools were used in this project:

- [Go](https://go.dev/)
- [UPX](https://upx.github.io/)

## :white_check_mark: Requirements ##

Before starting :checkered_flag:, you need to have [Git](https://git-scm.com),
[Go](https://go.dev/) and [UPX](https://upx.github.io/) installed.

## :checkered_flag: Starting ##

```bash
# Clone this project
$ git clone https://github.com/cyb3r3xpl0it/fastTCPScan

# Access
$ cd fastTCPScan

# Build the binary (stripped symbols and debug info)
$ go build -ldflags "-s -w" .

# Compress the binary with UPX
$ upx --brute fastTCPScan

# Install it system-wide
$ sudo mv fastTCPScan /usr/local/bin
```

Or use the **Makefile**, which wraps the whole flow:

```bash
$ make build      # compile
$ make test       # run unit tests
$ make install    # build + upx + move to /usr/local/bin
```

Run it with **Docker** (no Go toolchain required):

```bash
$ docker build -t fasttcpscan .
$ docker run --rm fasttcpscan -host scanme.nmap.org -top 100
```

## :wrench: Usage ##

```bash
# Scan all ports on a host
$ fastTCPScan -host 192.168.1.1

# Scan specific ports / ranges
$ fastTCPScan -host 192.168.1.1 -range 80,443,8000-9000

# Scan a whole subnet (CIDR) and a list of hosts (IPv4 or IPv6)
$ fastTCPScan -host 192.168.1.0/24,10.0.0.1 -range 22,80,443

# Scan only the N most common ports
$ fastTCPScan -host 192.168.1.1 -top 100

# Read targets from a file and discover live hosts first
$ fastTCPScan -iL targets.txt -top 100 -discover

# Service detection + banner grabbing
$ fastTCPScan -host scanme.nmap.org -range 1-1024 -banner

# Inspect TLS certificates on open ports
$ fastTCPScan -host github.com -range 443,8443 -tls

# CSV output to a file, with a global 5-minute deadline
$ fastTCPScan -host 192.168.1.0/24 -top 100 -format csv -o scan.csv -deadline 5m

# Tune concurrency, timeout and retries
$ fastTCPScan -host 192.168.1.1 -threads 2000 -timeout 500ms -retries 1

# UDP scan
$ fastTCPScan -host 192.168.1.1 -range 53,123,161 -proto udp

# Rate-limited, randomized scan saved to a file as JSON
$ fastTCPScan -host 192.168.1.1 -range 1-1024 -rate 500 -randomize -json -o results.json
```

| Flag         | Default       | Description                                                  |
| ------------ | ------------- | ----------------------------------------------------------- |
| `-host`      | `127.0.0.1`   | Host, IP, CIDR or comma-separated list (IPv4/IPv6)          |
| `-range`     | `1-65535`     | Ports to check: `80,443,1-65535,1000-2000, ...`             |
| `-top`       | `0`           | Scan only the N most common ports (overrides `-range`)      |
| `-iL`        | —             | Read targets from a file (one host/IP/CIDR per line)        |
| `-o`         | —             | Save results to a file instead of stdout                    |
| `-threads`   | `1000`        | Number of concurrent workers                                |
| `-timeout`   | `1s`          | Timeout per port (e.g. `500ms`, `2s`)                       |
| `-retries`   | `0`           | Retries per port before marking it closed                  |
| `-rate`      | `0`           | Limit of probes per second (`0` = unlimited)                |
| `-discover`  | `false`       | Discover live hosts (TCP ping) and skip the unresponsive    |
| `-randomize` | `false`       | Randomize host and port order                               |
| `-deadline`  | `0`           | Maximum total scan time (e.g. `5m`); `0` = unlimited        |
| `-proto`     | `tcp`         | Protocol to use: `tcp` or `udp`                             |
| `-banner`    | `false`       | Try to grab the service banner on open ports                |
| `-tls`       | `false`       | TLS handshake on open ports; show certificate details       |
| `-format`    | `text`        | Output format: `text`, `json`, `csv` or `grep`             |
| `-json`      | `false`       | Shortcut for `-format json`                                  |
| `-no-color`  | `false`       | Disable colored text output                                 |
| `-v` / `-q`  | `false`       | Verbose / quiet output                                       |
| `-all`       | `false`       | Also show closed/filtered ports                             |

## :memo: License ##

This project is under license from MIT. For more details, see the [LICENSE](LICENSE) file.


Made with :heart: by <a href="https://github.com/cyb3r3xpl0it" target="_blank">cyb3r3xpl0it</a>

&#xa0;

<a href="#top">Back to top</a>
