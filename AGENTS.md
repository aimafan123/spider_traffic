# Repository Guidelines

## Project Structure & Module Organization
- Core Python package: `src/spider_traffic/`.
- Entry flow: `src/spider_traffic/main.py` (orchestration) and `src/spider_traffic/action.py` (crawler execution).
- Key modules:
  - `spider/`: crawling logic, middleware, task scheduling.
  - `traffic/`: packet capture.
  - `tls_decoder/`: TLS/HTTP decode pipeline.
  - `myutils/`: config and logging helpers.
- Runtime/config assets:
  - `config/`: `config.ini`, URL/task configs.
  - `data/`: generated pcap, screenshots, downloads.
  - `logs/`: runtime logs.
  - `bin/`: bundled runtime binaries (Chrome/driver, Xray, Tor).

## Build, Test, and Development Commands
- Create env and install deps:
  ```bash
  python -m venv .venv
  . .venv/bin/activate
  pip install -r requirements.txt
  ```
- Run locally (recommended script):
  ```bash
  ./action.sh
  ```
- Equivalent direct run:
  ```bash
  cd src && ../.venv/bin/python3 -m spider_traffic.main
  ```
- Build container image:
  ```bash
  docker build -t aimafan/spider_traffic:v1 .
  ```

## Coding Style & Naming Conventions
- Follow PEP 8, 4-space indentation, and UTF-8 source files.
- Use `snake_case` for functions/variables/modules; `PascalCase` for classes.
- Keep side-effect code out of module import scope; place executable logic under `if __name__ == "__main__":`.
- Prefer small, focused functions and explicit logging via `myutils/logger.py`.

## Testing Guidelines
- This repo currently has limited automated tests; prioritize adding `pytest` tests under `tests/`.
- Naming convention: `tests/test_<feature>.py`, test functions `test_<behavior>()`.
- Run tests with:
  ```bash
  pytest -q
  ```
- For traffic features, include reproducible manual validation notes (input URL, mode, expected output files).

## Commit & Pull Request Guidelines
- Match existing commit style: `feat: ...`, `fix: ...`, `refactor: ...`, `docs: ...`.
- Keep each commit focused on one change set (config, crawler, decoder, etc.).
- PRs should include:
  - purpose and scope,
  - config changes (especially `config/config.ini` keys),
  - validation evidence (commands run, sample output paths),
  - screenshots/log snippets when behavior changes are visible.

## Security & Configuration Tips
- Do not commit sensitive endpoints, proxy credentials, or private IP mappings.
- Treat `config/config.ini` and generated `data/` as environment-specific artifacts.
- Verify required binaries in `bin/` and run capture components only in authorized environments.
