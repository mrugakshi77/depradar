from sqlalchemy import String, Text, Integer, Boolean, DateTime, Float, func, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.database import Base
from datetime import datetime
from typing import Optional, List


class PackageCache(Base):
    __tablename__ = "package_cache"
    __table_args__ = (UniqueConstraint('name_lower', 'pinned_version', name='uq_package_cache_name_version'),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(200), index=True, nullable=False)
    name_lower: Mapped[str] = mapped_column(String(200), index=True, nullable=False)
    pinned_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    latest_version: Mapped[Optional[str]] = mapped_column(String(50))
    summary: Mapped[Optional[str]] = mapped_column(Text)
    home_page: Mapped[Optional[str]] = mapped_column(String(500))
    license: Mapped[Optional[str]] = mapped_column(String(200))
    author: Mapped[Optional[str]] = mapped_column(String(300))
    pypi_classifiers: Mapped[Optional[str]] = mapped_column(Text)
    last_release_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    total_releases: Mapped[Optional[int]] = mapped_column(Integer)

    is_abandoned: Mapped[bool] = mapped_column(Boolean, default=False)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    deprecation_note: Mapped[Optional[str]] = mapped_column(Text)
    months_since_release: Mapped[Optional[float]] = mapped_column(Float)

    cve_data: Mapped[Optional[str]] = mapped_column(Text)
    cve_count: Mapped[int] = mapped_column(Integer, default=0)

    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    fetch_error: Mapped[Optional[str]] = mapped_column(Text)

    scan_packages: Mapped[List["ScanPackage"]] = relationship("ScanPackage", back_populates="cache_entry")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(String(12), unique=True, index=True, nullable=False)
    # manual | requirements | github
    source: Mapped[str] = mapped_column(String(20), default="manual")
    # For github scans: the repo URL that was scanned
    github_repo: Mapped[Optional[str]] = mapped_column(String(500))
    package_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[Optional[float]] = mapped_column(Float)

    outdated_count: Mapped[int] = mapped_column(Integer, default=0)
    abandoned_count: Mapped[int] = mapped_column(Integer, default=0)
    deprecated_count: Mapped[int] = mapped_column(Integer, default=0)
    vulnerable_count: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    packages: Mapped[List["ScanPackage"]] = relationship(
        "ScanPackage", back_populates="scan", cascade="all, delete-orphan"
    )


class ScanPackage(Base):
    __tablename__ = "scan_packages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), index=True)
    package_cache_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("package_cache.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    pinned_version: Mapped[Optional[str]] = mapped_column(String(50))

    is_outdated: Mapped[bool] = mapped_column(Boolean, default=False)
    is_abandoned: Mapped[bool] = mapped_column(Boolean, default=False)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    is_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_level: Mapped[str] = mapped_column(String(10), default="ok")
    latest_version: Mapped[Optional[str]] = mapped_column(String(50))
    cve_count: Mapped[int] = mapped_column(Integer, default=0)
    fetch_error: Mapped[Optional[str]] = mapped_column(Text)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="packages")
    cache_entry: Mapped[Optional["PackageCache"]] = relationship("PackageCache", back_populates="scan_packages")
