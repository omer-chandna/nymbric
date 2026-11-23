"""Lure orchestrator that ties together OSINT, generation, and delivery.

This module provides the main orchestration logic for the Nymbric lure framework,
connecting OSINT data collection, lure generation, and email delivery.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from nymbric.tools.osint import OSINTCollector, BreachedPKGLoader
from nymbric.tools.osint.aggregator import AggregatedEvidence
from nymbric.lures.real import LureGenerator, LureRenderer
from nymbric.tools.deliverer.transport.email import EmailTransport, DeliveryResult

logger = logging.getLogger(__name__)


@dataclass
class LureRunResult:
    """Result of a complete lure generation and delivery run."""

    target_name: str
    target_email: str | None = None
    target_employer: str | None = None
    target_location: str | None = None
    osint_sources: list[str] = field(default_factory=list)
    evidence_items: list[dict[str, Any]] = field(default_factory=list)
    generated_lures: list[dict[str, Any]] = field(default_factory=list)
    delivery_results: list[DeliveryResult] = field(default_factory=list)
    artifacts_dir: str = ""
    run_time: datetime = field(default_factory=datetime.now)
    success: bool = True
    error: str | None = None


class LureOrchestrator:
    """Orchestrates the complete lure generation and delivery pipeline.

    This class coordinates:
    1. OSINT data collection from multiple sources
    2. Evidence aggregation and deduplication
    3. Lure template selection and generation
    4. Artifact rendering and packaging
    5. Email delivery via SMTP
    """

    def __init__(
        self,
        output_dir: str = "lure_artifacts",
        breach_pkg_dir: str = "breached_pkgs",
        use_oauth2: bool = True,
        oauth2_client_id: str | None = None,
        oauth2_client_secret: str | None = None,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.breach_pkg_dir = Path(breach_pkg_dir)
        self.breach_pkg_dir.mkdir(parents=True, exist_ok=True)

        self.osint_collector = OSINTCollector()
        self.breach_pkg_loader = BreachedPKGLoader(breach_pkg_dir)
        self.lure_generator = LureGenerator()
        self.lure_renderer = LureRenderer(output_dir=output_dir)
        self.email_transport = EmailTransport(
            use_oauth2=use_oauth2,
            oauth2_client_id=oauth2_client_id,
            oauth2_client_secret=oauth2_client_secret,
        )

    def run(
        self,
        target_name: str,
        target_email: str | None = None,
        target_employer: str | None = None,
        target_location: str | None = None,
        link_url: str | None = None,
        sources: list[str] | None = None,
        template_name: str | None = None,
    ) -> LureRunResult:
        """Run the complete lure generation and delivery pipeline.

        Args:
            target_name: The target person's name.
            target_email: The target person's email.
            target_employer: The target's employer.
            target_location: The target's location.
            link_url: The user-controlled link URL to inject.
            sources: List of OSINT sources to query.
            template_name: The lure template to use.

        Returns:
            A LureRunResult containing all results.
        """
        result = LureRunResult(target_name=target_name)

        try:
            # Step 1: Collect OSINT data
            logger.info(f"Collecting OSINT data for: {target_name}")
            osint_result = self.osint_collector.collect(target_name, sources=sources)

            # Step 2: Scan breached PKG files
            logger.info("Scanning breached PKG files...")
            breached_files = self.breach_pkg_loader.scan(target_name)
            if breached_files:
                result.target_email = breached_files[0].extracted_emails[0] if breached_files[0].extracted_emails else None
                result.target_employer = breached_files[0].extracted_names[0] if breached_files[0].extracted_names else None
                result.target_location = breached_files[0].extracted_names[0] if breached_files[0].extracted_names else None

            # Step 3: Aggregate evidence
            logger.info("Aggregating evidence...")
            aggregated = AggregatedEvidence(
                target_name=osint_result.target_name or target_name,
                target_email=osint_result.target_email or target_email,
                target_employer=osint_result.target_employer or target_employer,
                target_location=osint_result.target_location or target_location,
                target_socials=osint_result.target_socials,
                target_links=osint_result.target_links,
                target_documents=osint_result.target_documents,
                target_breached_files=osint_result.target_breached_files,
                raw_evidence=osint_result.raw_evidence,
                sources=sources or [],
            )

            # Step 4: Generate lures
            logger.info("Generating lures...")
            lures = self.lure_generator.generate(
                target_name=target_name,
                target_email=target_email,
                target_employer=target_employer,
                target_location=target_location,
                link_url=link_url,
                template_name=template_name,
            )

            # Step 5: Render artifacts
            logger.info("Rendering artifacts...")
            for lure in lures:
                self.lure_renderer.render_json(lure)
                self.lure_renderer.render_yaml(lure)
                self.lure_renderer.package(lure)

            # Step 6: Deliver emails
            logger.info("Delivering emails...")
            if lures:
                results = self.email_transport.send_batch(
                    recipients=[target_email] if target_email else ["target@example.com"],
                    subject=lures[0].subject,
                    body=lures[0].body,
                    sender_name=lures[0].sender_name,
                    sender_email=lures[0].sender_email,
                    sender_address=lures[0].sender_address,
                    cc=lures[0].cc,
                    attachments=lures[0].attachments,
                )
                result.delivery_results = results

            result.evidence_items = [item.model_dump() for item in aggregated.to_evidence_items()]
            result.generated_lures = [lure.to_dict() for lure in lures]
            result.artifacts_dir = str(self.output_dir)
            result.success = True

        except Exception as e:
            logger.error(f"Orchestration failed: {e}")
            result.success = False
            result.error = str(e)

        return result

    def run_with_context(self, context: dict[str, Any]) -> LureRunResult:
        """Run the pipeline with a context dictionary.

        Args:
            context: A dictionary containing target information.

        Returns:
            A LureRunResult.
        """
        target_name = context.get("target_name")
        target_email = context.get("target_email")
        target_employer = context.get("target_employer")
        target_location = context.get("target_location")
        link_url = context.get("link_url")
        sources = context.get("sources")
        template_name = context.get("template_name")

        return self.run(
            target_name=target_name,
            target_email=target_email,
            target_employer=target_employer,
            target_location=target_location,
            link_url=link_url,
            sources=sources,
            template_name=template_name,
        )


def main() -> None:
    """CLI entry point for the lure orchestrator."""
    import argparse

    parser = argparse.ArgumentParser(description="Nymbric Lure Orchestrator")
    parser.add_argument("--target-name", required=True, help="Target person's name")
    parser.add_argument("--target-email", help="Target person's email")
    parser.add_argument("--target-employer", help="Target's employer")
    parser.add_argument("--target-location", help="Target's location")
    parser.add_argument("--link-url", help="User-controlled link URL")
    parser.add_argument("--sources", nargs="+", default=["linkedin", "github", "twitter", "news"],
                        help="OSINT sources to query")
    parser.add_argument("--template", default="job_offer", help="Lure template to use")
    parser.add_argument("--output-dir", default="lure_artifacts", help="Output directory")
    parser.add_argument("--breach-pkg-dir", default="breached_pkgs", help="Breached PKG directory")
    parser.add_argument("--use-oauth2", action="store_true", default=True, help="Use OAuth2 for email delivery")
    parser.add_argument("--oauth2-client-id", help="OAuth2 client ID")
    parser.add_argument("--oauth2-client-secret", help="OAuth2 client secret")

    args = parser.parse_args()

    orchestrator = LureOrchestrator(
        output_dir=args.output_dir,
        breach_pkg_dir=args.breach_pkg_dir,
        use_oauth2=args.use_oauth2,
        oauth2_client_id=args.oauth2_client_id,
        oauth2_client_secret=args.oauth2_client_secret,
    )

    result = orchestrator.run(
        target_name=args.target_name,
        target_email=args.target_email,
        target_employer=args.target_employer,
        target_location=args.target_location,
        link_url=args.link_url,
        sources=args.sources,
        template_name=args.template,
    )

    print(f"\n=== Lure Run Result ===")
    print(f"Target: {result.target_name}")
    print(f"Success: {result.success}")
    print(f"Error: {result.error}")
    print(f"Artifacts: {result.artifacts_dir}")
    print(f"Generated {len(result.generated_lures)} lures")
    print(f"Delivered {len(result.delivery_results)} emails")

    if result.evidence_items:
        print(f"\nEvidence items ({len(result.evidence_items)}):")
        for item in result.evidence_items:
            print(f"  - {item['predicate']}: {item['object']}")

    if result.generated_lures:
        print(f"\nGenerated lures ({len(result.generated_lures)}):")
        for lure in result.generated_lures:
            print(f"  - {lure['lure_id']}: {lure['subject']}")

    if result.delivery_results:
        print(f"\nDelivery results ({len(result.delivery_results)}):")
        for dr in result.delivery_results:
            print(f"  - {dr.recipient}: {'OK' if dr.success else 'FAILED'} - {dr.error or dr.message_id}")


if __name__ == "__main__":
    main()
