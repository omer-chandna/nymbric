"""OSINT tools for collecting real-world data about a target person.

This module provides tools that ingest personal context from external sources:
- LinkedIn profiles
- GitHub repositories and activity
- Twitter/X profiles
- News articles
- Breached PKG files (local storage)

All collected data is aggregated into EvidenceItem objects compatible with
the existing nymbric schema.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup

from nymbric.schemas.messages import EvidenceItem

logger = logging.getLogger(__name__)


class BreachedPKGLoader:
    """Loader for breached PKG files from local storage.

    This class provides functionality to load breached PKG files from
    local directories (e.g., ~/Documents, /var/spool/mail) and extract
    personal context data about target persons.
    """

    def __init__(self, base_path: str | Path | None = None):
        """Initialize the BreachedPKGLoader.

        Args:
            base_path: Base directory to scan for breached PKG files.
                Defaults to the current working directory.
        """
        self.base_path = Path(base_path) if base_path else Path.cwd()

    def scan(self, target_name: str) -> list[dict[str, Any]]:
        """Scan breached PKG files for the target person.

        Args:
            target_name: The name of the target person to search for.

        Returns:
            A list of dictionaries containing breached file information.
        """
        results: list[dict[str, Any]] = []

        # Scan the base path and subdirectories for breached PKG files
        for pkg_dir in self.base_path.rglob("*"):
            if not pkg_dir.is_dir():
                continue

            # Look for .pkg files or directories
            for file_path in pkg_dir.glob("*.pkg"):
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    if target_name.lower() in content.lower():
                        results.append({
                            "filename": file_path.name,
                            "path": str(file_path),
                            "content": content[:2000],
                            "sensitivity": "public",
                            "confidence": 0.95,
                        })
                except Exception:
                    continue

            # Also scan for any files in the directory
            for file_path in pkg_dir.rglob("*"):
                if file_path.is_file():
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="ignore")
                        if target_name.lower() in content.lower():
                            results.append({
                                "filename": file_path.name,
                                "path": str(file_path),
                                "content": content[:2000],
                                "sensitivity": "public",
                                "confidence": 0.95,
                            })
                    except Exception:
                        continue

        return results


@dataclass
class OSINTResult:
    """Result of an OSINT collection run."""

    target_name: str
    target_email: str | None = None
    target_phone: str | None = None
    target_location: str | None = None
    target_employer: str | None = None
    target_socials: dict[str, str] = field(default_factory=dict)
    target_links: list[str] = field(default_factory=list)
    target_documents: list[dict[str, Any]] = field(default_factory=list)
    target_breached_files: list[dict[str, Any]] = field(default_factory=list)
    raw_evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_evidence_items(self) -> list[EvidenceItem]:
        """Convert OSINT result to EvidenceItem objects."""
        items: list[EvidenceItem] = []

        if self.target_name:
            items.append(
                EvidenceItem(
                    evidence_id=f"osint-name-{self.target_name.lower().replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="has_name",
                    object=self.target_name,
                    confidence=1.0,
                    source_ref="osint",
                    source_kind="osint",
                    provenance="osint_aggregation",
                    excerpt=self.target_name,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        if self.target_email:
            items.append(
                EvidenceItem(
                    evidence_id=f"osint-email-{self.target_email.replace('.', '-').replace('@', '-').replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="has_email",
                    object=self.target_email,
                    confidence=0.9,
                    source_ref="osint",
                    source_kind="osint",
                    provenance="osint_aggregation",
                    excerpt=self.target_email,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        if self.target_phone:
            items.append(
                EvidenceItem(
                    evidence_id=f"osint-phone-{self.target_phone.replace('.', '-').replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="has_phone",
                    object=self.target_phone,
                    confidence=0.8,
                    source_ref="osint",
                    source_kind="osint",
                    provenance="osint_aggregation",
                    excerpt=self.target_phone,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        if self.target_location:
            items.append(
                EvidenceItem(
                    evidence_id=f"osint-location-{self.target_location.lower().replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="lives_in",
                    object=self.target_location,
                    confidence=0.85,
                    source_ref="osint",
                    source_kind="osint",
                    provenance="osint_aggregation",
                    excerpt=self.target_location,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        if self.target_employer:
            items.append(
                EvidenceItem(
                    evidence_id=f"osint-employer-{self.target_employer.lower().replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="works_at",
                    object=self.target_employer,
                    confidence=0.9,
                    source_ref="osint",
                    source_kind="osint",
                    provenance="osint_aggregation",
                    excerpt=self.target_employer,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        for social, url in self.target_socials.items():
            items.append(
                EvidenceItem(
                    evidence_id=f"osint-social-{social.lower()}-{url.replace('.', '-').replace('/', '-').replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="has_social",
                    object=social,
                    confidence=0.95,
                    source_ref="osint",
                    source_kind="osint",
                    provenance="osint_aggregation",
                    excerpt=f"{social}: {url}",
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        for link in self.target_links:
            items.append(
                EvidenceItem(
                    evidence_id=f"osint-link-{link.replace('.', '-').replace('/', '-').replace(' ', '-')}",
                    subject_id="osint-target",
                    predicate="has_link",
                    object=link,
                    confidence=0.9,
                    source_ref="osint",
                    source_kind="osint",
                    provenance="osint_aggregation",
                    excerpt=link,
                    sensitivity="public",
                    asserted=True,
                    kind="fact",
                    inference_status="observed",
                )
            )

        for doc in self.target_documents:
            items.append(
                EvidenceItem(
                    evidence_id=f"osint-doc-{doc.get('filename', 'unknown')}",
                    subject_id="osint-target",
                    predicate="has_document",
                    object=doc.get("filename", "unknown"),
                    confidence=doc.get("confidence", 0.9),
                    source_ref="osint",
                    source_kind="osint",
                    provenance="osint_aggregation",
                    excerpt=json.dumps(doc),
                    sensitivity=doc.get("sensitivity", "public"),
                    asserted=True,
                    kind="document",
                    inference_status="observed",
                )
            )

        for breached in self.target_breached_files:
            items.append(
                EvidenceItem(
                    evidence_id=f"osint-breach-{breached.get('filename', 'unknown')}",
                    subject_id="osint-target",
                    predicate="breached_file",
                    object=breached.get("filename", "unknown"),
                    confidence=breached.get("confidence", 0.95),
                    source_ref="osint",
                    source_kind="breach_pkg",
                    provenance="breached_pkg",
                    excerpt=json.dumps(breached),
                    sensitivity=breached.get("sensitivity", "public"),
                    asserted=True,
                    kind="breach",
                    inference_status="observed",
                )
            )

        return items


class OSINTCollector:
    """Collects OSINT data about a target person from various sources."""

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "Nymbric-OSINT/1.0 (https://nymbric.local)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
        })

    def collect(self, target_name: str, sources: list[str] | None = None) -> OSINTResult:
        """Collect OSINT data about a target person.

        Args:
            target_name: The name of the target person to research.
            sources: List of source types to query. Defaults to all available sources.

        Returns:
            OSINTResult containing all collected data.
        """
        result = OSINTResult(target_name=target_name)

        if sources is None:
            sources = ["linkedin", "github", "twitter", "news", "breach_pkg"]

        for source in sources:
            try:
                if source == "linkedin":
                    self._collect_linkedin(target_name, result)
                elif source == "github":
                    self._collect_github(target_name, result)
                elif source == "twitter":
                    self._collect_twitter(target_name, result)
                elif source == "news":
                    self._collect_news(target_name, result)
                elif source == "breach_pkg":
                    self._collect_breach_pkg(target_name, result)
                else:
                    logger.warning(f"Unknown OSINT source: {source}")
            except Exception as e:
                logger.warning(f"OSINT source {source} failed: {e}")

        return result

    def _collect_linkedin(self, target_name: str, result: OSINTResult) -> None:
        """Query LinkedIn for the target person."""
        try:
            url = f"https://www.linkedin.com/in/{target_name.lower().replace(' ', '-').replace('.', '-').replace(',', '')}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                profile = self._parse_linkedin(soup)
                if profile:
                    result.target_name = profile.get("name")
                    result.target_email = profile.get("email")
                    result.target_location = profile.get("location")
                    result.target_employer = profile.get("company")
                    result.target_socials["linkedin"] = url
                    result.target_links.append(url)
                    self._merge_into_existing(result)
            else:
                logger.debug(f"LinkedIn profile not found for {target_name}")
        except Exception as e:
            logger.warning(f"LinkedIn lookup for {target_name} failed: {e}")

    def _collect_github(self, target_name: str, result: OSINTResult) -> None:
        """Query GitHub for the target person."""
        try:
            url = f"https://github.com/{target_name.lower().replace(' ', '-').replace('.', '-').replace(',', '')}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                profile = self._parse_github(soup)
                if profile:
                    result.target_name = profile.get("name")
                    result.target_email = profile.get("email")
                    result.target_location = profile.get("location")
                    result.target_socials["github"] = url
                    result.target_links.append(url)
                    self._merge_into_existing(result)
            else:
                logger.debug(f"GitHub profile not found for {target_name}")
        except Exception as e:
            logger.warning(f"GitHub lookup for {target_name} failed: {e}")

    def _collect_twitter(self, target_name: str, result: OSINTResult) -> None:
        """Query Twitter/X for the target person."""
        try:
            url = f"https://twitter.com/{target_name.lower()}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                profile = self._parse_twitter(soup)
                if profile:
                    result.target_name = profile.get("name")
                    result.target_email = profile.get("email")
                    result.target_location = profile.get("location")
                    result.target_socials["twitter"] = url
                    result.target_links.append(url)
                    self._merge_into_existing(result)
            else:
                logger.debug(f"Twitter profile not found for {target_name}")
        except Exception as e:
            logger.warning(f"Twitter lookup for {target_name} failed: {e}")

    def _collect_news(self, target_name: str, result: OSINTResult) -> None:
        """Query news sources for the target person."""
        try:
            url = f"https://www.google.com/search?q={target_name.replace(' ', '+')}+site:linkedin.com"
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                results = self._parse_google_search(soup)
                if results:
                    for item in results[:5]:
                        result.target_links.append(item["url"])
                        result.raw_evidence.append({
                            "source": "google_news",
                            "title": item["title"],
                            "url": item["url"],
                            "snippet": item["snippet"],
                        })
                    self._merge_into_existing(result)
        except Exception as e:
            logger.warning(f"News lookup for {target_name} failed: {e}")

    def _collect_breach_pkg(self, target_name: str, result: OSINTResult) -> None:
        """Scan local breached PKG files for the target person."""
        try:
            breach_dir = Path("breached_pkgs")
            if not breach_dir.exists():
                return

            for pkg_dir in breach_dir.iterdir():
                if not pkg_dir.is_dir():
                    continue

                for file_path in pkg_dir.rglob("*"):
                    if file_path.is_file():
                        try:
                            content = file_path.read_text(encoding="utf-8", errors="ignore")
                            if target_name.lower() in content.lower():
                                result.target_breached_files.append({
                                    "filename": file_path.name,
                                    "path": str(file_path),
                                    "content": content[:2000],
                                    "sensitivity": "public",
                                    "confidence": 0.95,
                                })
                                self._merge_into_existing(result)
                        except Exception:
                            continue
        except Exception as e:
            logger.warning(f"Breach PKG scan failed: {e}")

    def _parse_linkedin(self, soup: BeautifulSoup) -> dict[str, Any] | None:
        """Parse LinkedIn profile HTML."""
        profile = {}

        name_elem = soup.select_one(".text-primary-headline")
        if name_elem:
            profile["name"] = name_elem.get_text(strip=True)

        email_elem = soup.select_one(".email-address")
        if email_elem:
            profile["email"] = email_elem.get_text(strip=True)

        location_elem = soup.select_one(".text-secondary-link")
        if location_elem:
            profile["location"] = location_elem.get_text(strip=True)

        company_elem = soup.select_one(".text-primary-link")
        if company_elem:
            profile["company"] = company_elem.get_text(strip=True)

        return profile if profile else None

    def _parse_github(self, soup: BeautifulSoup) -> dict[str, Any] | None:
        """Parse GitHub profile HTML."""
        profile = {}

        name_elem = soup.select_one(".vcard-summary-fullname")
        if name_elem:
            profile["name"] = name_elem.get_text(strip=True)

        email_elem = soup.select_one(".vcard-summary-email")
        if email_elem:
            profile["email"] = email_elem.get_text(strip=True)

        location_elem = soup.select_one(".vcard-summary-location")
        if location_elem:
            profile["location"] = location_elem.get_text(strip=True)

        return profile if profile else None

    def _parse_twitter(self, soup: BeautifulSoup) -> dict[str, Any] | None:
        """Parse Twitter/X profile HTML."""
        profile = {}

        name_elem = soup.select_one(".profile-bio-fullname")
        if name_elem:
            profile["name"] = name_elem.get_text(strip=True)

        email_elem = soup.select_one(".profile-bio-email")
        if email_elem:
            profile["email"] = email_elem.get_text(strip=True)

        location_elem = soup.select_one(".profile-bio-location")
        if location_elem:
            profile["location"] = location_elem.get_text(strip=True)

        return profile if profile else None

    def _parse_google_search(self, soup: BeautifulSoup) -> list[dict[str, Any]]:
        """Parse Google search results."""
        results = []
        for result in soup.select(".g"):
            title_elem = result.select_one(".g yt5")
            url_elem = result.select_one(".g a")
            snippet_elem = result.select_one(".g yf")
            if title_elem and url_elem:
                results.append({
                    "title": title_elem.get_text(strip=True),
                    "url": url_elem.get("href", ""),
                    "snippet": snippet_elem.get_text(strip=True) if snippet_elem else "",
                })
        return results

    def _merge_into_existing(self, result: OSINTResult) -> None:
        """Merge result into an existing OSINTResult, keeping the best data."""
        if not hasattr(self, "_existing"):
            self._existing = OSINTResult(target_name=result.target_name)
        else:
            self._existing = result

        if result.target_name:
            self._existing.target_name = result.target_name
        if result.target_email:
            self._existing.target_email = result.target_email
        if result.target_phone:
            self._existing.target_phone = result.target_phone
        if result.target_location:
            self._existing.target_location = result.target_location
        if result.target_employer:
            self._existing.target_employer = result.target_employer
        for social, url in result.target_socials.items():
            if social not in self._existing.target_socials:
                self._existing.target_socials[social] = url
        for link in result.target_links:
            if link not in self._existing.target_links:
                self._existing.target_links.append(link)
        for doc in result.target_documents:
            if doc.get("filename") not in [d.get("filename") for d in self._existing.target_documents]:
                self._existing.target_documents.append(doc)
        for breached in result.target_breached_files:
            if breached.get("filename") not in [b.get("filename") for b in self._existing.target_breached_files]:
                self._existing.target_breached_files.append(breached)
        for evidence in result.raw_evidence:
            if evidence.get("url") not in [e.get("url") for e in self._existing.raw_evidence]:
                self._existing.raw_evidence.append(evidence)