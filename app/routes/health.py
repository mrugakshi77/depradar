import httpx
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.db.database import get_db
from app.schemas.package import HealthResponse
from app.core.config import settings
from app.services.github import check_github_reachability

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse, summary="Health check")
async def health(db: AsyncSession = Depends(get_db)):
    db_status = "ok"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {e}"

    pypi_status = "ok"
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{settings.PYPI_BASE_URL}/requests/json", timeout=5.0)
            if r.status_code != 200:
                pypi_status = f"http {r.status_code}"
    except Exception as e:
        pypi_status = f"error: {e}"

    osv_status = "ok"
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{settings.OSV_BASE_URL}/query",
                json={"package": {"name": "requests", "ecosystem": "PyPI"}},
                timeout=5.0,
            )
            if r.status_code != 200:
                osv_status = f"http {r.status_code}"
    except Exception as e:
        osv_status = f"error: {e}"

    github_status = await check_github_reachability()

    return HealthResponse(
        status="ok" if db_status == "ok" else "degraded",
        version=settings.APP_VERSION,
        database=db_status,
        pypi=pypi_status,
        osv=osv_status,
        github=github_status,
    )
