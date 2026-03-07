import asyncio
import json
import logging
import random
import string
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple

from packaging.version import Version, InvalidVersion
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.package import PackageCache, Scan, ScanPackage
from app.schemas.package import PackageInput, CVEEntry, PackageResult
from app.services.pypi import fetch_package_data

logger = logging.getLogger(__name__)


def _make_scan_id(length: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _is_cache_stale(cache: PackageCache) -> bool:
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=settings.CACHE_TTL_HOURS)
    ts = cache.updated_at
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts < cutoff


def _is_outdated(pinned: Optional[str], latest: Optional[str]) -> bool:
    if not pinned or not latest:
        return False
    try:
        return Version(pinned) < Version(latest)
    except InvalidVersion:
        return False


def _risk_level(is_outdated: bool, is_abandoned: bool, is_deprecated: bool,
                is_vulnerable: bool, cve_count: int) -> str:
    if is_vulnerable and cve_count > 0:
        return "critical"
    if is_deprecated:
        return "high"
    if is_abandoned:
        return "medium"
    if is_outdated:
        return "low"
    return "ok"


def _overall_risk_score(packages: List[ScanPackage]) -> float:
    if not packages:
        return 0.0
    weights = {"critical": 40, "high": 25, "medium": 15, "low": 5, "ok": 0}
    total = sum(weights.get(p.risk_level, 0) for p in packages)
    max_possible = 40 * len(packages)
    return round((total / max_possible) * 100, 1)


async def _get_or_refresh_cache_isolated(name: str, pinned: Optional[str]) -> PackageCache:
    from app.db.database import AsyncSessionLocal
    name_lower = name.lower()

    async with AsyncSessionLocal() as session:
        cache_key_version = pinned
        result = await session.execute(
            select(PackageCache).where(
                PackageCache.name_lower == name_lower,
                PackageCache.pinned_version == cache_key_version,
            )
        )
        cache = result.scalar_one_or_none()

        if cache and not _is_cache_stale(cache):
            logger.info(f"Cache hit: {name}")
            cache_id = cache.id
        else:
            logger.info(f"Fetching from PyPI/OSV: {name}")
            data = await fetch_package_data(name, pinned)

            if cache:
                for k, v in data.items():
                    setattr(cache, k, v)
                cache.updated_at = datetime.now(tz=timezone.utc)
            else:
                data['pinned_version'] = pinned
                cache = PackageCache(**data)
                session.add(cache)

            await session.flush()
            cache_id = cache.id
            await session.commit()

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PackageCache).where(PackageCache.id == cache_id)
        )
        return result.scalar_one()

async def _get_or_refresh_cache(
    db: AsyncSession, name: str, pinned: Optional[str]
) -> PackageCache:
    return await _get_or_refresh_cache_isolated(name, pinned)


async def run_scan(
    db: AsyncSession,
    packages: List[PackageInput],
    source: str = "manual",
    github_repo: Optional[str] = None,
) -> Scan:
    seen: dict = {}
    for pkg in packages:
        if pkg.name not in seen:
            seen[pkg.name] = pkg
    unique = list(seen.values())

    semaphore = asyncio.Semaphore(settings.SCAN_CONCURRENCY)

    async def fetch_one(pkg: PackageInput) -> Tuple[PackageInput, Optional[PackageCache]]:
        async with semaphore:
            try:
                cache = await _get_or_refresh_cache_isolated(pkg.name, pkg.version)
                return pkg, cache
            except Exception as e:
                logger.error(f"Error fetching {pkg.name}: {e}")
                return pkg, None

    fetched = await asyncio.gather(*[fetch_one(p) for p in unique])

    scan = Scan(
        scan_id=_make_scan_id(),
        source=source,
        github_repo=github_repo,
        package_count=len(unique),
    )
    db.add(scan)
    await db.flush()

    scan_packages = []
    for pkg, cache in fetched:
        if cache is None or cache.fetch_error:
            sp = ScanPackage(
                scan_id=scan.id,
                name=pkg.name,
                pinned_version=pkg.version,
                risk_level="ok",
                fetch_error=cache.fetch_error if cache else "Fetch failed",
            )
        else:
            outdated = _is_outdated(pkg.version, cache.latest_version)
            vulnerable = cache.cve_count > 0
            rl = _risk_level(outdated, cache.is_abandoned, cache.is_deprecated, vulnerable, cache.cve_count)
            sp = ScanPackage(
                scan_id=scan.id,
                package_cache_id=cache.id,
                name=cache.name,
                pinned_version=pkg.version,
                is_outdated=outdated,
                is_abandoned=cache.is_abandoned,
                is_deprecated=cache.is_deprecated,
                is_vulnerable=vulnerable,
                risk_level=rl,
                latest_version=cache.latest_version,
                cve_count=cache.cve_count,
            )
        scan_packages.append(sp)

    db.add_all(scan_packages)
    await db.flush()

    scan.outdated_count = sum(1 for sp in scan_packages if sp.is_outdated)
    scan.abandoned_count = sum(1 for sp in scan_packages if sp.is_abandoned)
    scan.deprecated_count = sum(1 for sp in scan_packages if sp.is_deprecated)
    scan.vulnerable_count = sum(1 for sp in scan_packages if sp.is_vulnerable)
    scan.risk_score = _overall_risk_score(scan_packages)

    await db.flush()
    await db.refresh(scan)
    return scan


async def get_scan(db: AsyncSession, scan_id: str) -> Optional[Scan]:
    result = await db.execute(select(Scan).where(Scan.scan_id == scan_id))
    return result.scalar_one_or_none()


async def get_scan_packages(db: AsyncSession, scan_db_id: int) -> List[ScanPackage]:
    result = await db.execute(select(ScanPackage).where(ScanPackage.scan_id == scan_db_id))
    return list(result.scalars().all())


def build_package_result(sp: ScanPackage, cache: Optional[PackageCache]) -> PackageResult:
    cves = []
    if cache and cache.cve_data:
        try:
            cves = [CVEEntry(**c) for c in json.loads(cache.cve_data)]
        except Exception:
            pass
    return PackageResult(
        name=sp.name,
        pinned_version=sp.pinned_version,
        latest_version=sp.latest_version,
        is_outdated=sp.is_outdated,
        is_abandoned=sp.is_abandoned,
        is_deprecated=sp.is_deprecated,
        is_vulnerable=sp.is_vulnerable,
        risk_level=sp.risk_level,
        months_since_release=cache.months_since_release if cache else None,
        deprecation_note=cache.deprecation_note if cache else None,
        cve_count=sp.cve_count,
        cves=cves,
        fetch_error=sp.fetch_error,
    )
