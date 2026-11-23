"""Web scraping utilities for OSINT data collection.

This module provides low-level scraping utilities that are used by the
OSINTCollector to gather data from various sources.
"""

from __future__ import annotations

import logging
from typing import Any

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def scrape_url(url: str, timeout: int = 10) -> dict[str, Any]:
    """Scrape a single URL and return its parsed content.

    Args:
        url: The URL to scrape.
        timeout: Request timeout in seconds.

    Returns:
        A dictionary containing the scraped data.
    """
    try:
        response = requests.get(url, timeout=timeout, headers={
            "User-Agent": "Nymbric-OSINT/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        return {
            "url": url,
            "status_code": response.status_code,
            "title": soup.title.string if soup.title else "",
            "content": response.text[:10000],
            "soup": soup,
        }
    except requests.exceptions.RequestException as e:
        logger.warning(f"Failed to scrape {url}: {e}")
        return {"url": url, "error": str(e)}


def extract_email_from_html(html: str) -> str | None:
    """Extract email addresses from HTML content.

    Args:
        html: The HTML content to search.

    Returns:
        The first email address found, or None.
    """
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("a", href=True):
        href = tag.get("href", "")
        if "@" in href and not href.startswith(("http://", "https://")):
            return href
    for tag in soup.find_all("a", href=True):
        href = tag.get("href", "")
        if "@" in href:
            return href
    return None


def extract_links_from_html(html: str) -> list[str]:
    """Extract all links from HTML content.

    Args:
        html: The HTML content to search.

    Returns:
        A list of URLs found in the HTML.
    """
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag.get("href", "")
        if href and not href.startswith(("javascript:", "mailto:", "tel:")):
            links.append(href)
    return links


def extract_social_links_from_html(html: str) -> dict[str, str]:
    """Extract social media links from HTML content.

    Args:
        html: The HTML content to search.

    Returns:
        A dictionary mapping social network names to their URLs.
    """
    soup = BeautifulSoup(html, "html.parser")
    socials = {}

    # Common social media URL patterns
    social_patterns = {
        "linkedin": r"(https?://(?:www\.)?linkedin\.com/in/[\w-]+)",
        "github": r"(https?://github\.com/[\w-]+)",
        "twitter": r"(https?://(?:www\.)?twitter\.com/[\w-]+)",
        "instagram": r"(https?://(?:www\.)?instagram\.com/[\w-]+)",
        "facebook": r"(https?://(?:www\.)?facebook\.com/[\w-]+)",
        "website": r"(https?://[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}(?:/[^\s]*)?)",
    }

    for pattern, name in social_patterns.items():
        matches = re.findall(pattern, html)
        if matches:
            socials[name] = matches[0]

    return socials


def extract_location_from_html(html: str) -> str | None:
    """Extract location information from HTML content.

    Args:
        html: The HTML content to search.

    Returns:
        The location string, or None if not found.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Try common location selectors
    selectors = [
        ".vcard-summary-location",
        ".profile-bio-location",
        ".text-secondary-link",
        ".location",
        "[data-testid=\"location\"]",
    ]

    for selector in selectors:
        elem = soup.select_one(selector)
        if elem and elem.get_text(strip=True):
            return elem.get_text(strip=True)

    return None


def extract_company_from_html(html: str) -> str | None:
    """Extract company/employer information from HTML content.

    Args:
        html: The HTML content to search.

    Returns:
        The company name, or None if not found.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Try common company selectors
    selectors = [
        ".text-primary-link",
        ".company-name",
        ".vcard-summary-org",
        "[data-testid=\"company\"]",
    ]

    for selector in selectors:
        elem = soup.select_one(selector)
        if elem and elem.get_text(strip=True):
            return elem.get_text(strip=True)

    return None
