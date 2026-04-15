# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**demon** is a Go-based security/penetration testing toolkit (資訊安全) containing port scanning, SSH brute force, reverse shell, and keylogging tools. Educational and authorized security testing use only.

## Build & Run

```bash
make build       # Compiles all 5 binaries into bin/
make clean       # Removes compiled binaries
```

Individual binaries can be built directly:
```bash
go build -o bin/Scan.out demo/scan/main.go
go build -o bin/Boom.out demo/sshBoom/main.go
go build -o bin/Reserver.out demo/reverse/re_server/ReverseShellServer.go
go build -o bin/Reclient.out demo/reverse/re_client/ReverseShellClient.go
go build -o bin/Keylog.out demo/keylogger/keylogger.go
```

No test suite exists. The Makefile mentions `make test` but it is not implemented.

## Architecture

The project follows a `demo/` + `internal/` pattern:

- **`demo/`** — Executable main programs (each is a standalone tool)
  - `scan/` — Full port scanner (1-65535), concurrent goroutines, reports known service vulnerabilities
  - `sshBoom/` — SSH brute force with wordlists (`user.txt`, `password.txt`), 10 worker threads, progress bar, pprof profiling
  - `reverse/re_server/` — TCP reverse shell server (listens `:30002`, spawns `/bin/sh`)
  - `reverse/re_client/` — Reverse shell client (connects to server, sends commands, `Q` to exit)
  - `keylogger/` — Keyboard input capture using eiannone/keyboard library

- **`internal/`** — Shared libraries used by demo programs
  - `scan/` — Port parsing (supports formats: `80`, `80,81`, `80-83`, `80~85`, `80|81|82`) and vulnerability mapping for 50+ common ports
  - `attack/` — SSH login attempts via `golang.org/x/crypto/ssh`, reverse shell client logic, SQL injection placeholder
  - `logger/` — Uber Zap wrapper with custom timestamp `[YYYY-MM-DD HH:MM:SS.mmm]` and level formatting
  - `dblib/` — MySQL connection wrapper using `go-sql-driver/mysql`
  - `help/` — File I/O utilities (line-by-line file reading)

## Key Dependencies

- `golang.org/x/crypto` — SSH client operations
- `go.uber.org/zap` — Structured logging
- `github.com/schollz/progressbar/v3` — CLI progress bars
- `github.com/eiannone/keyboard` — Keyboard input capture
- `github.com/go-sql-driver/mysql` — MySQL driver

Module: `demon`, Go 1.16. Manage deps with `go mod tidy`.

## Conventions

- All demo programs log to `./log/demon.log` at Info level
- Binaries are output to `bin/` directory
- The project language is a mix of Go code with Chinese (Traditional) comments and documentation
