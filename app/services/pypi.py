import httpx
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from app.core.config import settings

logger = logging.getLogger(__name__)

DEPRECATION_CLASSIFIERS = {
    "Development Status :: 7 - Inactive",
    "Development Status :: X - Deprecated (do not use)",
}

DEPRECATION_KEYWORDS = [
    "deprecated", "unmaintained", "abandoned", "no longer maintained",
    "use instead", "replaced by", "superseded", "archived",
]


class PyPIClient:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def fetch(self, name: str) -> Optional[Dict[str, Any]]:
        try:
            r = await self.client.get(f"{settings.PYPI_BASE_URL}/{name}/json", timeout=15.0)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except httpx.HTTPError as e:
            logger.error(f"PyPI fetch error for {name}: {e}")
            return None


class OSVClient:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def query_vulns(self, name: str, version: Optional[str] = None) -> List[Dict]:
        payload: Dict[str, Any] = {"package": {"name": name, "ecosystem": "PyPI"}}
        if version:
            payload["version"] = version
        try:
            r = await self.client.post(f"{settings.OSV_BASE_URL}/query", json=payload, timeout=15.0)
            r.raise_for_status()
            return r.json().get("vulns", [])
        except httpx.HTTPError as e:
            logger.error(f"OSV query error for {name}: {e}")
            return []


def _months_since(dt: datetime) -> float:
    now = datetime.now(tz=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return round((now - dt).days / 30.44, 1)


def _parse_last_release(pypi_data: Dict) -> Optional[datetime]:
    latest_dt = None
    for version_files in pypi_data.get("releases", {}).values():
        for f in version_files:
            upload_str = f.get("upload_time_iso_8601") or f.get("upload_time")
            if not upload_str:
                continue
            try:
                dt = datetime.fromisoformat(upload_str.replace("Z", "+00:00"))
                if latest_dt is None or dt > latest_dt:
                    latest_dt = dt
            except ValueError:
                pass
    return latest_dt


def _detect_deprecation(pypi_data: Dict) -> tuple[bool, Optional[str]]:
    info = pypi_data.get("info", {})
    classifiers: List[str] = info.get("classifiers", []) or []
    for c in classifiers:
        if c in DEPRECATION_CLASSIFIERS:
            return True, f"Classifier: {c}"
    for field in ("summary", "description"):
        text = (info.get(field) or "").lower()
        for kw in DEPRECATION_KEYWORDS:
            if kw in text:
                idx = text.find(kw)
                snippet = text[max(0, idx - 20): idx + 60].strip()
                return True, f'Contains "{kw}": …{snippet}…'
    return False, None


def _parse_osv_vulns(vulns: List[Dict]) -> List[Dict]:
    results = []
    for v in vulns:
        severity = None
        for s in v.get("severity", []):
            if s.get("type") == "CVSS_V3":
                raw = s.get("score", 0) or 0
                try:
                    score = float(raw)
                    severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
                except (ValueError, TypeError):
                    severity = "medium"  # fallback if score is a vector string
        aliases = v.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
        refs = v.get("references", [])
        results.append({
            "id": cve_id,
            "summary": (v.get("summary") or "")[:300],
            "severity": severity,
            "published": v.get("published", "")[:10],
            "url": refs[0].get("url") if refs else None,
        })
    return results


async def fetch_package_data(name: str, pinned_version: Optional[str] = None) -> Dict[str, Any]:
    async with httpx.AsyncClient() as http:
        pypi = PyPIClient(http)
        osv = OSVClient(http)

        pypi_data = await pypi.fetch(name)
        if not pypi_data:
            return {"name": name, "name_lower": name.lower(), "fetch_error": f"'{name}' not found on PyPI"}

        info = pypi_data.get("info", {})
        classifiers: List[str] = info.get("classifiers", []) or []
        last_release_date = _parse_last_release(pypi_data)
        months_since = _months_since(last_release_date) if last_release_date else None
        is_abandoned = months_since is not None and months_since > settings.ABANDONMENT_THRESHOLD_MONTHS
        is_deprecated, deprecation_note = _detect_deprecation(pypi_data)

        vulns_raw = await osv.query_vulns(name, pinned_version)
        cves = _parse_osv_vulns(vulns_raw)

        return {
            "name": info.get("name", name),
            "name_lower": name.lower(),
            "latest_version": info.get("version"),
            "summary": (info.get("summary") or "")[:500] or None,
            "home_page": info.get("home_page") or info.get("project_url"),
            "license": (info.get("license") or "")[:200] or None,
            "author": (info.get("author") or "")[:300] or None,
            "pypi_classifiers": json.dumps(classifiers),
            "last_release_date": last_release_date,
            "total_releases": len(pypi_data.get("releases", {})),
            "is_abandoned": is_abandoned,
            "is_deprecated": is_deprecated,
            "deprecation_note": deprecation_note,
            "months_since_release": months_since,
            "cve_data": json.dumps(cves),
            "cve_count": len(cves),
            "fetch_error": None,
        }
