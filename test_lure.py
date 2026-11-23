#!/usr/bin/env python
"""Simple test for the Nymbric Lure Framework."""

from __future__ import annotations

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from nymbric.orchestration.lure_orchestrator import LureOrchestrator


def test_basic_run() -> None:
    """Test a basic lure generation and delivery run."""
    orchestrator = LureOrchestrator(
        output_dir="test_artifacts",
        breach_pkg_dir="test_breached_pkgs",
        use_oauth2=False,  # Disable OAuth2 for testing
    )

    result = orchestrator.run(
        target_name="John Doe",
        target_email="john.doe@example.com",
        target_employer="Acme Corporation",
        target_location="San Francisco, CA",
        link_url="https://example.com/phishing-link",
        sources=["linkedin", "github", "twitter", "news"],
        template_name="job_offer",
    )

    assert result.success, f"Run failed: {result.error}"
    assert result.target_name == "John Doe"
    assert len(result.generated_lures) == 1
    assert result.generated_lures[0]["subject"].startswith("Urgent: Your Job Offer")
    assert "Acme Corporation" in result.generated_lures[0]["subject"]
    assert "john.doe@example.com" in result.generated_lures[0]["subject"]
    assert "https://example.com/phishing-link" in result.generated_lures[0]["body"]

    print("[PASS] Basic run test passed")


def test_security_alert_template() -> None:
    """Test security alert template."""
    orchestrator = LureOrchestrator(
        output_dir="test_artifacts",
        breach_pkg_dir="test_breached_pkgs",
        use_oauth2=False,
    )

    result = orchestrator.run(
        target_name="Jane Smith",
        target_email="jane.smith@acme.com",
        target_employer="Acme Corp",
        target_location="New York, NY",
        link_url="https://acme.com/login",
        template_name="security_alert",
    )

    assert result.success
    assert "SECURITY ALERT" in result.generated_lures[0]["subject"]
    assert "compromised" in result.generated_lures[0]["body"].lower()

    print("[PASS] Security alert template test passed")


def test_invoice_template() -> None:
    """Test invoice template."""
    orchestrator = LureOrchestrator(
        output_dir="test_artifacts",
        breach_pkg_dir="test_breached_pkgs",
        use_oauth2=False,
    )

    result = orchestrator.run(
        target_name="Bob Wilson",
        target_email="bob.wilson@company.com",
        target_employer="TechStart Inc",
        target_location="Austin, TX",
        link_url="https://techstart.com/pay",
        template_name="invoice",
    )

    assert result.success
    assert "Invoice" in result.generated_lures[0]["subject"]
    assert "payment" in result.generated_lures[0]["body"].lower()

    print("[PASS] Invoice template test passed")


def test_multiple_templates() -> None:
    """Test generating multiple lure types."""
    orchestrator = LureOrchestrator(
        output_dir="test_artifacts",
        breach_pkg_dir="test_breached_pkgs",
        use_oauth2=False,
    )

    result = orchestrator.run(
        target_name="Alice Brown",
        target_email="alice.brown@company.com",
        target_employer="GlobalTech",
        target_location="Seattle, WA",
        link_url="https://globaltech.com/phish",
        template_name="meeting_invite",
    )

    assert result.success
    assert "Meeting Invitation" in result.generated_lures[0]["subject"]
    assert "Q4 planning" in result.generated_lures[0]["body"]

    print("[PASS] Multiple templates test passed")


def test_artifacts_generated() -> None:
    """Test that artifacts are properly generated."""
    orchestrator = LureOrchestrator(
        output_dir="test_artifacts",
        breach_pkg_dir="test_breached_pkgs",
        use_oauth2=False,
    )

    result = orchestrator.run(
        target_name="Charlie Davis",
        target_email="charlie@company.com",
        target_employer="BetaCorp",
        target_location="Chicago, IL",
        link_url="https://betacorp.com/phish",
        template_name="package_delivery",
    )

    assert result.success
    assert result.artifacts_dir == "test_artifacts"
    assert len(result.generated_lures) == 1

    # Check that artifacts were created (ZIP archives)
    artifacts_dir = Path("test_artifacts")
    import glob
    zip_files = list(artifacts_dir.glob("lure-*.zip"))
    assert len(zip_files) > 0, f"No ZIP files found in {artifacts_dir}"

    print("[PASS] Artifacts generated test passed")


if __name__ == "__main__":
    test_basic_run()
    test_security_alert_template()
    test_invoice_template()
    test_multiple_templates()
    test_artifacts_generated()
    print("[PASS] All tests passed!")
