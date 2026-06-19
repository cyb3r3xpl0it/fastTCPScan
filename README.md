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
:heavy_check_mark: TCP, UDP and **SYN half-open** scanning (`-syn`, Linux + root);\
:heavy_check_mark: Service detection, **version detection** (`-sV`), banner grabbing and TLS certificate inspection (`-tls`);\
:heavy_check_mark: **SOCKS5 proxy** support (`-proxy`) and **reverse DNS** (`-rdns`);\
:heavy_check_mark: Target/port **exclusion lists** (`-exclude`, `-exclude-ports`);\
:heavy_check_mark: Configurable timeout and retries per port;\
:heavy_check_mark: Multiple output formats: `text`, `json`, `csv`, `grep`, **`xml`** (Nmap-style) and **`html`** report;\
:heavy_check_mark: **Resume/checkpoint** of interrupted scans (`-resume`);\
:heavy_check_mark: **Scan profiles** (`-profile fast/full/stealth/web`) and **config files** (`-config`);\
:heavy_check_mark: **Shell completions** for bash, zsh and fish (`-completion`);\
:heavy_check_mark: Colored output (auto-disabled when piped) and verbosity levels (`-v` / `-q`);\
:heavy_check_mark: Global deadline (`-deadline`), file-descriptor auto-tuning and adaptive concurrency;\
:heavy_check_mark: Live **progress bar with rate and ETA**, and clean Ctrl+C cancellation;\
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

# Service version detection + reverse DNS, HTML report
$ fastTCPScan -host 192.168.1.0/24 -top 100 -sV -rdns -format html -o report.html

# CSV output to a file, with a global 5-minute deadline
$ fastTCPScan -host 192.168.1.0/24 -top 100 -format csv -o scan.csv -deadline 5m

# SYN half-open scan (Linux, needs root)
$ sudo fastTCPScan -host 192.168.1.1 -top 1000 -syn

# Scan through a SOCKS5 proxy, excluding some hosts/ports
$ fastTCPScan -host 10.0.0.0/24 -top 100 -proxy 127.0.0.1:1080 -exclude 10.0.0.1 -exclude-ports 22

# Resumable scan: re-run the same command to continue where it stopped
$ fastTCPScan -host 192.168.1.0/24 -range 1-65535 -resume scan.checkpoint

# Use a built-in profile (fast / full / stealth / web)
$ fastTCPScan -host 192.168.1.1 -profile web

# Load options from a config file (command-line flags still win)
$ fastTCPScan -config scan.conf -host 192.168.1.1

# Generate shell completions
$ fastTCPScan -completion bash > /etc/bash_completion.d/fastTCPScan
$ fastTCPScan -completion zsh  > "${fpath[1]}/_fastTCPScan"
$ fastTCPScan -completion fish > ~/.config/fish/completions/fastTCPScan.fish
```

A **config file** is a simple `key = value` list using the same names as the flags:

```ini
# scan.conf
top     = 100
timeout = 800ms
sV      = true
range   = 1-1000
```

Options precedence (highest first): **command-line flags → `-config` file → `-profile` → defaults**.

```bash
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
| `-syn`       | `false`       | SYN half-open scan (Linux, requires root)                  |
| `-proxy`     | —             | SOCKS5 proxy for TCP connections (`[user:pass@]host:port`) |
| `-banner`    | `false`       | Try to grab the service banner on open ports                |
| `-sV`        | `false`       | Service version detection on open ports                     |
| `-tls`       | `false`       | TLS handshake on open ports; show certificate details       |
| `-rdns`      | `false`       | Reverse-DNS (PTR) lookup of hosts with results              |
| `-exclude`   | —             | Hosts/IP/CIDR to exclude (comma-separated)                  |
| `-exclude-ports` | —         | Ports to exclude (e.g. `22,80,8000-8100`)                  |
| `-resume`    | —             | Checkpoint file to save/resume progress                     |
| `-profile`   | —             | Scan profile: `fast`, `full`, `stealth` or `web`           |
| `-config`    | —             | Config file (`key = value` per line)                       |
| `-completion`| —             | Print shell completion script: `bash`, `zsh` or `fish`     |
| `-format`    | `text`        | Output format: `text`, `json`, `csv`, `grep`, `xml`, `html` |
| `-json`      | `false`       | Shortcut for `-format json`                                  |
| `-no-color`  | `false`       | Disable colored text output                                 |
| `-v` / `-q`  | `false`       | Verbose / quiet output                                       |
| `-all`       | `false`       | Also show closed/filtered ports                             |

## :hammer_and_wrench: Development ##

```bash
$ make test     # unit tests
$ make cover    # tests with race detector + coverage report
$ make fuzz     # fuzz the port/CIDR parsers (FUZZTIME=30s by default)
$ make lint     # golangci-lint (govet, staticcheck, ineffassign, unused, gofmt)
$ make vet      # go vet
```

CI (GitHub Actions) runs vet, tests with the race detector and coverage
(uploaded to Codecov), golangci-lint and a cross-compilation matrix on every
push and pull request.

## :lock: Verifying releases ##

Release binaries are built by [GoReleaser](https://goreleaser.com/), shipped
with an **SBOM** per archive and a `checksums.txt` **signed with
[cosign](https://github.com/sigstore/cosign)** (keyless / Sigstore). To verify:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature  checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/cyb3r3xpl0it/fastTCPScan' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

# Then check your binary against the verified checksums:
sha256sum -c checksums.txt --ignore-missing
```

## :memo: License ##

This project is under license from MIT. For more details, see the [LICENSE](LICENSE) file.


Made with :heart: by <a href="https://github.com/cyb3r3xpl0it" target="_blank">cyb3r3xpl0it</a>

&#xa0;

<a href="#top">Back to top</a>
