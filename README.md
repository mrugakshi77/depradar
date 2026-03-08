# DepRadar v2 — Python Dependency Risk Scanner

**Live demo: [depradar.onrender.com](https://depradar.onrender.com)** | **API docs: [depradar.onrender.com/docs](https://depradar.onrender.com/docs)**

Scan Python dependencies for four categories of risk. Supports `requirements.txt` upload, direct GitHub repository scanning, a REST API, and a CLI tool that integrates with CI/CD pipelines.

---

## What it detects

| Signal | Source | Logic |
|---|---|---|
| **Outdated** | PyPI JSON API | Pinned version < latest version (using `packaging.version`) |
| **Abandoned** | PyPI release history | No release in 24+ months (configurable) |
| **Deprecated** | PyPI classifiers + description text | `Development Status :: 7 - Inactive` classifier, or keywords like "deprecated", "replaced by", "unmaintained" in summary |
| **Vulnerable** | OSV.dev API | Known CVEs — precise when version is pinned with `==` |

---

## Architecture

```
depradar/
├── app/
│   ├── core/config.py          # pydantic-settings, all env vars
│   ├── db/database.py          # async SQLAlchemy engine + session DI
│   ├── models/package.py       # PackageCache, Scan, ScanPackage ORM models
│   ├── schemas/package.py      # Pydantic v2 I/O schemas
│   ├── services/
│   │   ├── pypi.py             # Async PyPI + OSV.dev clients, risk detection
│   │   ├── github.py           # GitHub URL parser + raw file fetcher
│   │   ├── parser.py           # requirements.txt parser (handles all spec formats)
│   │   └── scan_service.py     # Bounded fan-out, cache logic, risk scoring
│   ├── routes/
│   │   ├── scan.py             # POST /scan, /scan/requirements, /scan/github + GET /scan/{id}
│   │   ├── package.py          # GET /package/{name}
│   │   └── health.py           # GET /health (DB, PyPI, OSV, GitHub)
│   └── main.py
├── cli/
│   └── depradar.py             # Typer CLI with rich output
├── frontend/index.html         # Single-file SPA — no build step
├── setup.py                    # Makes `depradar` an installable CLI command
├── Dockerfile
├── docker-compose.yml
└── .env
```

### Key engineering decisions

**Bounded async fan-out** — `asyncio.gather` + `asyncio.Semaphore(10)` fires all package lookups in parallel. Scan time is proportional to the slowest single package, not the sum of all packages.

**Two-layer caching** — `PackageCache` stores one row per PyPI package, TTL-refreshed every 12 hours. `ScanPackage` denormalises risk flags at scan time so report retrieval is a single DB query.

**Risk scoring** — Weighted sum normalised to 0–100: critical=40pts, high=25pts, medium=15pts, low=5pts per package.

**GitHub integration** — Hits the GitHub Repos API to resolve the default branch, then fetches the raw file from `raw.githubusercontent.com`. Supports a `GITHUB_TOKEN` for private repos and higher rate limits.

---

## Quick start

```bash
git clone https://github.com/mrugakshi77/depradar
cd depradar
pixi run db-setup
pixi run dev
```

- **Frontend**: http://localhost:8000
- **Swagger docs**: http://localhost:8000/docs
- **Live demo**: https://depradar.onrender.com

---

## CLI

Install locally (outside Docker):

```bash
pip install -e .
```

### `depradar scan` — scan a requirements.txt

```bash
depradar scan requirements.txt
depradar scan requirements.txt --fail-on high
depradar scan requirements.txt --fail-on critical --json
depradar scan requirements.txt --api http://my-server:8000
```

`--fail-on` exits with code 1 if any package reaches the specified risk level or higher. Perfect for CI:

```yaml
# .github/workflows/deps.yml
- name: Dependency risk scan
  run: depradar scan requirements.txt --fail-on high
```

### `depradar github` — scan a GitHub repo

```bash
depradar github https://github.com/psf/requests
depradar github https://github.com/django/django --ref stable/4.2.x --path requirements/base.txt
depradar github https://github.com/owner/repo --fail-on critical
```

### `depradar package` — single package lookup

```bash
depradar package requests
depradar package requests --version 2.28.0
```

### `depradar status` — check API health

```bash
depradar status
depradar status --api http://my-server:8000
```

---

## API Reference

### `GET /health`
```bash
curl http://localhost:8000/health
```
```json
{ "status": "ok", "version": "2.0.0", "database": "ok", "pypi": "ok", "osv": "ok", "github": "ok (60 req remaining)" }
```

### `POST /scan` — package list
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"packages": [{"name": "requests", "version": "2.28.0"}, {"name": "flask"}]}'
```

### `POST /scan/requirements` — requirements.txt content
```bash
curl -X POST http://localhost:8000/scan/requirements \
  -H "Content-Type: application/json" \
  -d "{\"content\": $(cat requirements.txt | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')}"
```

### `POST /scan/github` — GitHub repository
```bash
curl -X POST http://localhost:8000/scan/github \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/psf/requests"}'

# With branch and custom path:
curl -X POST http://localhost:8000/scan/github \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/django/django",
    "ref": "stable/4.2.x",
    "requirements_path": "requirements/base.txt"
  }'
```

### `GET /scan/{scan_id}` — retrieve past scan
```bash
curl http://localhost:8000/scan/ab3k9mxzqt
```

### `GET /package/{name}` — single package
```bash
curl http://localhost:8000/package/requests
curl "http://localhost:8000/package/requests?version=2.28.0"
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Dependency Risk Scan
on: [push, pull_request]

jobs:
  depradar:
    runs-on: ubuntu-latest
    services:
      depradar:
        image: your-registry/depradar:latest
        ports: ["8000:8000"]
    steps:
      - uses: actions/checkout@v4
      - run: pip install depradar-cli
      - run: depradar scan requirements.txt --fail-on high --api http://localhost:8000
```

### Or via direct API call in CI

```bash
# Fail the build if risk score > 50 or any critical CVEs exist
RESULT=$(curl -s -X POST http://localhost:8000/scan/requirements \
  -H "Content-Type: application/json" \
  -d "{\"content\": $(cat requirements.txt | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')}")

SCORE=$(echo $RESULT | python3 -c "import sys,json; print(json.load(sys.stdin)['risk_score'])")
CRITICAL=$(echo $RESULT | python3 -c "import sys,json; d=json.load(sys.stdin); print(sum(1 for p in d['packages'] if p['risk_level']=='critical'))")

if (( $(echo "$SCORE > 50" | bc -l) )) || [ "$CRITICAL" -gt "0" ]; then
  echo "Dependency scan failed: score=$SCORE critical=$CRITICAL"
  exit 1
fi
```

---

## Configuration (`.env`)

```env
DATABASE_URL=postgresql+asyncpg://radaruser:radarpass@db:5432/radardb
ABANDONMENT_THRESHOLD_MONTHS=24    # Lower = stricter
CACHE_TTL_HOURS=12                 # Re-fetch PyPI data frequency
SCAN_CONCURRENCY=10                # Max parallel PyPI/OSV requests
GITHUB_TOKEN=ghp_xxxx              # Optional: higher rate limits + private repos
```

---

## Resume bullets

```
DepRadar — Python Dependency Risk Scanner (github.com/mrugakshi77/depradar | depradar.onrender.com)
• Built an async REST API (FastAPI + SQLAlchemy 2.0) that parallelises dependency
  metadata and CVE retrieval across PyPI and OSV.dev using bounded asyncio concurrency
• Designed a PostgreSQL caching layer with TTL-based refresh, reducing repeat scan
  latency from ~10s to <50ms for cached results
• Implemented a GitHub repository scanner (POST /scan/github) that resolves branches
  via the GitHub API and fetches requirements files directly from raw.githubusercontent.com
• Built a CLI tool (depradar scan requirements.txt --fail-on high) for CI/CD pipeline
  integration with structured exit codes and rich terminal output
• Containerised the full stack with Docker Compose; deployed publicly at [url]
```
