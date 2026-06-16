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
:heavy_check_mark: Flexible port ranges (`80,443,1-65535,1000-2000, ...`);\
:heavy_check_mark: Configurable connection timeout per port;\
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
$ go build -ldflags "-s -w" fastTCPScan.go

# Compress the binary with UPX
$ upx --brute fastTCPScan

# Install it system-wide
$ sudo mv fastTCPScan /usr/local/bin
```

## :wrench: Usage ##

```bash
# Scan all ports on a host
$ fastTCPScan -host 192.168.1.1

# Scan specific ports / ranges
$ fastTCPScan -host 192.168.1.1 -range 80,443,8000-9000

# Tune concurrency and timeout
$ fastTCPScan -host 192.168.1.1 -threads 2000 -timeout 500ms
```

| Flag        | Default       | Description                                         |
| ----------- | ------------- | --------------------------------------------------- |
| `-host`     | `127.0.0.1`   | Host or IP address to scan                          |
| `-range`    | `1-65535`     | Ports to check: `80,443,1-65535,1000-2000, ...`     |
| `-threads`  | `1000`        | Number of concurrent workers                        |
| `-timeout`  | `1s`          | Timeout per port (e.g. `500ms`, `2s`)               |

## :memo: License ##

This project is under license from MIT. For more details, see the [LICENSE](LICENSE) file.


Made with :heart: by <a href="https://github.com/cyb3r3xpl0it" target="_blank">cyb3r3xpl0it</a>

&#xa0;

<a href="#top">Back to top</a>
