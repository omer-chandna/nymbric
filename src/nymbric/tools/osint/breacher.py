"""Breached PKG loader for local files.

This module provides tools to load and scan breached PKG files
(e.g., from ~/Documents, /var/spool/mail, or other local storage)
for evidence about a target person.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BreachedFile:
    """Represents a breached PKG file found during scanning."""

    filename: str
    path: str
    content: str
    sensitivity: str = "public"
    confidence: float = 0.95
    matched_patterns: list[str] = field(default_factory=list)
    extracted_emails: list[str] = field(default_factory=list)
    extracted_links: list[str] = field(default_factory=list)
    extracted_names: list[str] = field(default_factory=list)


class BreachedPKGLoader:
    """Loader for breached PKG files from local storage.

    Scans directories containing breached PKG files and extracts
    relevant information about a target person.
    """

    def __init__(self, base_path: str | Path = "breached_pkgs"):
        self.base_path = Path(base_path)

    def scan(self, target_name: str) -> list[BreachedFile]:
        """Scan all breached PKG files for the target person.

        Args:
            target_name: The name of the target person to search for.

        Returns:
            A list of BreachedFile objects containing matched files.
        """
        results: list[BreachedFile] = []

        if not self.base_path.exists():
            logger.info(f"Breached PKG directory not found: {self.base_path}")
            return results

        # Pattern to match the target name in file content
        target_pattern = re.compile(
            re.escape(target_name.lower()),
            re.IGNORECASE
        )

        # Scan all files in the breached_pkgs directory
        for pkg_dir in self.base_path.iterdir():
            if not pkg_dir.is_dir():
                continue

            logger.info(f"Scanning breached PKG directory: {pkg_dir}")

            for file_path in pkg_dir.rglob("*"):
                if not file_path.is_file():
                    continue

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                # Check if the target name appears in the file
                if target_name.lower() in content.lower():
                    # Extract emails
                    emails = self._extract_emails(content)
                    # Extract links
                    links = self._extract_links(content)
                    # Extract names
                    names = self._extract_names(content)

                    result = BreachedFile(
                        filename=file_path.name,
                        path=str(file_path),
                        content=content[:5000],  # Truncate for readability
                        sensitivity="public",
                        confidence=0.95,
                        matched_patterns=[target_name],
                        extracted_emails=emails,
                        extracted_links=links,
                        extracted_names=names,
                    )
                    results.append(result)
                    logger.info(f"  Found match in: {file_path.name}")

        return results

    def scan_directory(self, directory: str | Path, target_name: str) -> list[BreachedFile]:
        """Scan a specific directory for breached PKG files.

        Args:
            directory: The directory to scan.
            target_name: The target person's name.

        Returns:
            A list of BreachedFile objects.
        """
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.warning(f"Directory not found: {directory}")
            return []

        results: list[BreachedFile] = []
        target_pattern = re.compile(re.escape(target_name.lower()), re.IGNORECASE)

        for file_path in dir_path.rglob("*"):
            if not file_path.is_file():
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            if target_name.lower() in content.lower():
                emails = self._extract_emails(content)
                links = self._extract_links(content)
                names = self._extract_names(content)

                result = BreachedFile(
                    filename=file_path.name,
                    path=str(file_path),
                    content=content[:5000],
                    sensitivity="public",
                    confidence=0.95,
                    matched_patterns=[target_name],
                    extracted_emails=emails,
                    extracted_links=links,
                    extracted_names=names,
                )
                results.append(result)

        return results

    def _extract_emails(self, content: str) -> list[str]:
        """Extract email addresses from content.

        Args:
            content: The text content to search.

        Returns:
            A list of email addresses found.
        """
        email_pattern = re.compile(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            re.IGNORECASE
        )
        return email_pattern.findall(content)

    def _extract_links(self, content: str) -> list[str]:
        """Extract URLs from content.

        Args:
            content: The text content to search.

        Returns:
            A list of URLs found.
        """
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        return url_pattern.findall(content)

    def _extract_names(self, content: str) -> list[str]:
        """Extract potential names from content.

        Args:
            content: The text content to search.

        Returns:
            A list of potential names found.
        """
        # Common name patterns
        name_patterns = [
            r'[A-Z][a-z]+ [A-Z][a-z]+',  # First Last
            r'[A-Z][a-z]+ [A-Z][a-z]+ [A-Z][a-z]+',  # First Middle Last
            r'[A-Z][a-z]+ [A-Z][a-z]+ [A-Z][a-z]+ [A-Z][a-z]+',  # Full name
        ]

        names = []
        for pattern in name_patterns:
            matches = re.findall(pattern, content)
            names.extend(matches)

        return list(set(names))

    def load_file(self, file_path: str | Path) -> BreachedFile | None:
        """Load a single breached PKG file.

        Args:
            file_path: Path to the file to load.

        Returns:
            A BreachedFile object, or None if the file couldn't be loaded.
        """
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"File not found: {file_path}")
            return None

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.warning(f"Failed to read file {file_path}: {e}")
            return None

        return BreachedFile(
            filename=path.name,
            path=str(path),
            content=content[:5000],
            sensitivity="public",
            confidence=0.95,
        )
