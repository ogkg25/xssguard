# XSSGuard

XSSGuard is a **dual-approach** XSS security tool:

- **White-box**: static scanning with AST taint tracking, PHP patterns, sanitization-aware analysis.
- **Black-box**: dynamic scanning with stored XSS revisit, context-aware payloads, header injection, SPA crawling.
- **Sanitizer**: HTML sanitization with an allowlist-style policy.

This repo intentionally keeps documentation **in this single file**. (The `docs/` dissertation files are academic artifacts and not required for usage.)

> **Responsible use:** Only scan systems you own or have explicit permission to test. Do not use XSSGuard against third-party sites without authorization.

## Install

```bash
pip install -e ".[dev]"  # installs runtime + dev dependencies (pytest, black, etc.)
```

Optional (only needed for `blackbox --verify` or SPA crawling):

```bash
python -m playwright install chromium
```

## Usage (CLI)

- **White-box scan** (file or directory):

```bash
xssguard whitebox <path>
```

- **Black-box scan** (URL, optional crawl):

```bash
xssguard blackbox <url> --crawl --depth 2
```

- **Sanitize HTML**:

```bash
xssguard sanitize --input unsafe.html --output-file safe.html
```

### Practical flags (the ones you’ll actually use)

- **Output**: `--output console|json|html` and `-f/--output-file <path>` (note: console output does not support `-f`)
- **White-box filtering / CI**: `--min-severity low|medium|high|critical`, `--fail-on low|medium|high|critical`
- **White-box strict mode**: `--strict` (ignore sanitizers, report all findings)
- **Black-box crawling**: `--crawl`, `--depth <n>`, `--max-pages <n>`
- **Black-box scope control** (cuts noise): `--scope '/path/prefix/'`
- **Black-box auth**: `--cookie 'PHPSESSID=...'`
- **Verification** (raises confidence, slower): `--verify`

## Configuration

If present, `xssguard.yaml` is loaded automatically; you can also pass `--config path/to/file.yaml`.

## Testing

```bash
pytest             # or: make test
```

## Benchmarking (reproducible)

**Quick start** (synthetic benchmarks, no Docker):

```bash
make benchmark-synthetic    # runs smoke tests against local fixtures
```

**Full suite** (requires Docker containers):

```bash
make benchmark              # runs all targets (synthetic + DVWA + Juice Shop)
```

---

**Prerequisites** (once):

```bash
pip install -e ".[dev]"
docker compose -f benchmarks/docker-compose.bench.yml pull   # pre-pull images
```

> On Apple Silicon or Linux arm64, Docker uses Rosetta/QEMU for the amd64-only images
> (DVWA, OWASP Benchmark). This is handled automatically by the compose file.

---

### 1. Smoke tests — fast, no Docker required (synthetic)

Synthetic whitebox + blackbox scan against local test fixtures, compared to stored baselines:

```bash
python3 benchmarks/run_smoke_test.py
```

Specific modes:

```bash
python3 benchmarks/run_smoke_test.py --mode whitebox
python3 benchmarks/run_smoke_test.py --mode blackbox
python3 benchmarks/run_smoke_test.py --mode matrix    # type × context coverage matrix
```

Outputs: `benchmarks/results/matrix_raw_results.json`, `benchmarks/results/matrix_report.json`

Regenerate baselines only when intentionally changing detection behaviour:

```bash
python3 benchmarks/run_smoke_test.py --generate
```

---

### 2. DVWA — real-world reflected/stored/DOM XSS

```bash
# Start DVWA
docker compose -f benchmarks/docker-compose.bench.yml up -d dvwa

# First-time setup: Initialize DVWA database
# 1. Open http://localhost:8081 in browser
# 2. Click "Create / Reset Database" button on setup page
# 3. Login with: admin / password
# 4. Open DevTools (F12) → Application → Cookies
# 5. Copy PHPSESSID value from cookies

# Save cookie for authentication
# Create file: benchmarks/real_world/.dvwa_cookie
# Content: PHPSESSID=your_session_id; security=low

# Run (17 cases: reflected/stored/DOM × low/medium/high/impossible + attribute/js contexts)
python3 benchmarks/real_world/run_dvwa_matrix.py --dvwa-url http://localhost:8081 --verify

# Optional filters
python3 benchmarks/real_world/run_dvwa_matrix.py --xss-type reflected --context html_body
```

Outputs: `benchmarks/results/real_world/dvwa_matrix_raw_results.json` + `dvwa_matrix_report.json`

---

### 3. Juice Shop — modern JS framework XSS

```bash
# Start Juice Shop
docker compose -f benchmarks/docker-compose.bench.yml up -d juiceshop

# Run (6 cases: API XSS, CSP bypass, stored feedback, etc.)
python3 benchmarks/real_world/run_juiceshop_matrix.py --verify
```

Outputs: `benchmarks/results/real_world/juiceshop_matrix_raw_results.json` + `juiceshop_matrix_report.json`

---

### 4. OWASP Benchmark — Java/Tomcat (2,740+ test cases)

```bash
# Start (first run is slow: Maven downloads dependencies, ~2–3 min)
docker compose -f benchmarks/docker-compose.bench.yml up -d owasp

# Auto-start Docker and run (uses --ensure-docker flag)
python3 benchmarks/real_world/run_owasp_benchmark.py --owasp-url https://localhost:8443/benchmark --ensure-docker
```

Output: `benchmarks/results/real_world/owasp_results.json`

---

### Aggregate reporting (dissertation-ready tables)

After running benchmarks, generate aggregate P/R/F1 metrics with per-target and per-context breakdowns:

```bash
python3 benchmarks/aggregate_report.py \
  benchmarks/results/matrix_report.json \
  benchmarks/results/real_world/dvwa_matrix_report.json \
  benchmarks/results/real_world/juiceshop_matrix_report.json \
  -o benchmarks/results/aggregate_report.json
```

Outputs:
- `benchmarks/results/aggregate_report.json` — full metrics (TP/FP/FN/TN, P/R/F1, macro averages)
- `benchmarks/results/dissertation_tables.md` — formatted markdown tables

## License & safety

- **License**: MIT (see `LICENSE`)
- **Safety**: Only scan systems you own or have explicit permission to test.
