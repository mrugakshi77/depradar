import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.package import PackageCache
from app.schemas.package import PackageLookupResult, CVEEntry
from app.services.scan_service import _get_or_refresh_cache

router = APIRouter(prefix="/package", tags=["Packages"])


@router.get("/{name}", response_model=PackageLookupResult, summary="Look up a single package")
async def get_package(
    name: str,
    version: str = Query(None, description="Optional pinned version for precise CVE matching"),
    db: AsyncSession = Depends(get_db),
):
    cache = await _get_or_refresh_cache(db, name.lower(), version)
    if cache.fetch_error:
        raise HTTPException(status_code=404, detail=cache.fetch_error)

    cves = []
    if cache.cve_data:
        try:
            cves = [CVEEntry(**c) for c in json.loads(cache.cve_data)]
        except Exception:
            pass

    return PackageLookupResult(
        name=cache.name,
        latest_version=cache.latest_version,
        summary=cache.summary,
        home_page=cache.home_page,
        license=cache.license,
        author=cache.author,
        last_release_date=cache.last_release_date,
        months_since_release=cache.months_since_release,
        is_abandoned=cache.is_abandoned,
        is_deprecated=cache.is_deprecated,
        deprecation_note=cache.deprecation_note,
        cve_count=cache.cve_count,
        cves=cves,
        fetched_at=cache.fetched_at,
    )
