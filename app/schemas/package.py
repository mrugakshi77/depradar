from pydantic import BaseModel, ConfigDict, Field, field_validator
from datetime import datetime
from typing import Optional, List


# ── Inputs ────────────────────────────────────────────────────────────────────

class PackageInput(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    version: Optional[str] = Field(None, max_length=50)

    @field_validator("name")
    @classmethod
    def clean_name(cls, v: str) -> str:
        return v.strip().lower()


class ScanRequest(BaseModel):
    packages: List[PackageInput] = Field(..., min_length=1, max_length=500)
    source: str = Field("manual", pattern="^(manual|requirements)$")


class RequirementsUpload(BaseModel):
    content: str = Field(..., description="Raw requirements.txt content")


class GithubScanRequest(BaseModel):
    repo_url: str = Field(
        ...,
        description="GitHub repository URL, e.g. https://github.com/owner/repo",
        examples=["https://github.com/psf/requests"],
    )
    ref: Optional[str] = Field(
        None,
        description="Branch, tag, or commit SHA. Defaults to the repo's default branch.",
    )
    requirements_path: str = Field(
        "requirements.txt",
        description="Path to requirements file within the repo",
    )


# ── CVE ───────────────────────────────────────────────────────────────────────

class CVEEntry(BaseModel):
    id: str
    summary: Optional[str] = None
    severity: Optional[str] = None
    published: Optional[str] = None
    url: Optional[str] = None


# ── Per-package result ────────────────────────────────────────────────────────

class PackageResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    pinned_version: Optional[str]
    latest_version: Optional[str]
    is_outdated: bool
    is_abandoned: bool
    is_deprecated: bool
    is_vulnerable: bool
    risk_level: str
    months_since_release: Optional[float] = None
    deprecation_note: Optional[str] = None
    cve_count: int = 0
    cves: List[CVEEntry] = []
    fetch_error: Optional[str] = None


# ── Scan report ───────────────────────────────────────────────────────────────

class ScanReport(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scan_id: str
    source: str
    github_repo: Optional[str] = None
    package_count: int
    risk_score: Optional[float]
    outdated_count: int
    abandoned_count: int
    deprecated_count: int
    vulnerable_count: int
    created_at: datetime
    packages: List[PackageResult]


# ── Single package lookup ─────────────────────────────────────────────────────

class PackageLookupResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    latest_version: Optional[str]
    summary: Optional[str]
    home_page: Optional[str]
    license: Optional[str]
    author: Optional[str]
    last_release_date: Optional[datetime]
    months_since_release: Optional[float]
    is_abandoned: bool
    is_deprecated: bool
    deprecation_note: Optional[str]
    cve_count: int
    cves: List[CVEEntry] = []
    fetched_at: datetime


# ── Health ────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    pypi: str
    osv: str
    github: str
