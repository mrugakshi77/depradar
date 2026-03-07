from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.database import get_db
from app.models.package import ScanPackage, PackageCache
from app.schemas.package import (
    ScanRequest, ScanReport, RequirementsUpload,
    GithubScanRequest, PackageInput,
)
from app.services.scan_service import run_scan, get_scan, get_scan_packages, build_package_result
from app.services.parser import parse_requirements
from app.services.github import parse_github_url, fetch_requirements_from_github

import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scan", tags=["Scans"])


@router.post("", response_model=ScanReport, summary="Scan a package list")
async def create_scan(req: ScanRequest, db: AsyncSession = Depends(get_db)):
    scan = await run_scan(db, req.packages, source=req.source)
    return await _build_report(db, scan)


@router.post(
    "/requirements",
    response_model=ScanReport,
    summary="Scan a requirements.txt",
    description="POST raw requirements.txt content.",
)
async def scan_requirements(payload: RequirementsUpload, db: AsyncSession = Depends(get_db)):
    parsed = parse_requirements(payload.content)
    if not parsed:
        raise HTTPException(status_code=422, detail="No valid packages found in requirements.txt")
    packages = [PackageInput(name=n, version=v) for n, v in parsed]
    scan = await run_scan(db, packages, source="requirements")
    return await _build_report(db, scan)


@router.post(
    "/github",
    response_model=ScanReport,
    summary="Scan a GitHub repository",
    description=(
        "Fetches the requirements file from a public GitHub repository "
        "and runs a full dependency risk scan. Optionally specify a branch, "
        "tag, or commit SHA via `ref`, and a custom path via `requirements_path`."
    ),
)
async def scan_github(req: GithubScanRequest, db: AsyncSession = Depends(get_db)):
    # Parse and validate the GitHub URL
    try:
        owner, repo = parse_github_url(req.repo_url)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # Fetch the requirements file
    try:
        content = await fetch_requirements_from_github(
            owner, repo, req.ref, req.requirements_path
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    parsed = parse_requirements(content)
    if not parsed:
        raise HTTPException(
            status_code=422,
            detail=f"No valid packages found in '{req.requirements_path}' at {req.repo_url}",
        )

    packages = [PackageInput(name=n, version=v) for n, v in parsed]
    repo_url_clean = f"https://github.com/{owner}/{repo}"
    scan = await run_scan(db, packages, source="github", github_repo=repo_url_clean)
    return await _build_report(db, scan)


@router.get("/{scan_id}", response_model=ScanReport, summary="Retrieve a past scan")
async def get_scan_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return await _build_report(db, scan)


async def _build_report(db, scan) -> ScanReport:
    scan_packages = await get_scan_packages(db, scan.id)
    cache_ids = [sp.package_cache_id for sp in scan_packages if sp.package_cache_id]
    cache_map = {}
    if cache_ids:
        result = await db.execute(
            select(PackageCache).where(PackageCache.id.in_(cache_ids))
        )
        for c in result.scalars().all():
            cache_map[c.id] = c

    package_results = [
        build_package_result(sp, cache_map.get(sp.package_cache_id))
        for sp in scan_packages
    ]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
    package_results.sort(key=lambda p: order.get(p.risk_level, 5))

    return ScanReport(
        scan_id=scan.scan_id,
        source=scan.source,
        github_repo=scan.github_repo,
        package_count=scan.package_count,
        risk_score=scan.risk_score,
        outdated_count=scan.outdated_count,
        abandoned_count=scan.abandoned_count,
        deprecated_count=scan.deprecated_count,
        vulnerable_count=scan.vulnerable_count,
        created_at=scan.created_at,
        packages=package_results,
    )
