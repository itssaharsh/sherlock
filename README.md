# Sherlock

Youtube : https://youtu.be/gHk5yqSgsVc
Sherlock is a Bitcoin chain-analysis toolkit that parses raw block data and applies transaction heuristics to produce JSON and Markdown intelligence reports.

It provides:
- A CLI pipeline for block-file level analysis.
- A web visualizer and API for browsing generated reports.
- Documented heuristics and trade-offs in `APPROACH.md`.

## Features

- Parse `blk*.dat`, `rev*.dat`, and `xor.dat` inputs.
- Analyze transactions with multiple heuristics (CIOH, change detection, consolidation, coinjoin signals, and more).
- Generate:
  - `out/<blk_stem>.json`
  - `out/<blk_stem>.md`
- Serve analysis over HTTP.

## Requirements

- Go 1.21+

## Quick Start

```bash
./setup.sh
./cli.sh --block fixtures/blk04330.dat fixtures/rev04330.dat fixtures/xor.dat
./web.sh
```

## CLI Usage

```bash
./cli.sh --block <blk.dat> <rev.dat> <xor.dat>
```

## Web API

- `GET /api/health`
- `GET /api/blocks`
- `GET /api/block/<name>`

## Project Layout

- `cmd/cli`: analysis CLI
- `cmd/web`: API + static UI server
- `internal/parser`: block/tx parsing
- `internal/analysis`: heuristics engine
- `internal/output`: JSON/Markdown output formatting
- `web/ui`: frontend assets

## Notes

This project is standalone and repository-scoped outputs are generated in `out/` at runtime.
