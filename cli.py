#!/usr/bin/env python
"""CLI entry point for the Nymbric Lure Framework.

Usage:
    python cli.py --target-name "John Doe" --target-email "john@example.com"
    python cli.py --target-name "Jane Smith" --target-employer "Acme Corp" --link-url "https://example.com/phish"
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from nymbric.orchestration.lure_orchestrator import LureOrchestrator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Nymbric Lure Framework - Generate and deliver phishing lures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py --target-name "John Doe" --target-email "john@example.com"
  python cli.py --target-name "Jane Smith" --target-employer "Acme Corp" --link-url "https://example.com/phish"
  python cli.py --target-name "Bob Wilson" --sources linkedin github --template security_alert
        """
    )

    parser.add_argument("--target-name", required=True, help="Target person's name")
    parser.add_argument("--target-email", help="Target person's email")
    parser.add_argument("--target-employer", help="Target's employer")
    parser.add_argument("--target-location", help="Target's location")
    parser.add_argument("--link-url", help="User-controlled link URL to inject")
    parser.add_argument("--sources", nargs="+", default=["linkedin", "github", "twitter", "news"],
                        help="OSINT sources to query (default: linkedin github twitter news)")
    parser.add_argument("--template", default="job_offer",
                        choices=["job_offer", "invoice", "meeting_invite", "security_alert", "package_delivery", "renewal_notice"],
                        help="Lure template to use")
    parser.add_argument("--output-dir", default="lure_artifacts", help="Output directory for artifacts")
    parser.add_argument("--breach-pkg-dir", default="breached_pkgs", help="Breached PKG directory")
    parser.add_argument("--use-oauth2", action="store_true", default=True, help="Use OAuth2 for email delivery")
    parser.add_argument("--oauth2-client-id", help="OAuth2 client ID")
    parser.add_argument("--oauth2-client-secret", help="OAuth2 client secret")
    parser.add_argument("--dry-run", action="store_true", help="Don't actually send emails")

    args = parser.parse_args()

    orchestrator = LureOrchestrator(
        output_dir=args.output_dir,
        breach_pkg_dir=args.breach_pkg_dir,
        use_oauth2=args.use_oauth2,
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

    print(f"\n{'='*60}")
    print(f"  Nymbric Lure Framework - Run Complete")
    print(f"{'='*60}")
    print(f"  Target:        {result.target_name}")
    print(f"  Success:       {result.success}")
    print(f"  Error:         {result.error or 'None'}")
    print(f"  Artifacts:     {result.artifacts_dir}")
    print(f"  Generated:     {len(result.generated_lures)} lures")
    print(f"  Delivered:     {len(result.delivery_results)} emails")
    print(f"{'='*60}\n")

    if result.evidence_items:
        print("  Evidence collected:")
        for item in result.evidence_items:
            print(f"    • {item['predicate']}: {item['object']} (confidence: {item['confidence']})")

    if result.generated_lures:
        print(f"\n  Generated lures:")
        for lure in result.generated_lures:
            print(f"    • {lure['lure_id']}: {lure['subject']}")
            print(f"      Sender: {lure['sender_name']} <{lure['sender_email']}>")
            print(f"      Urgency: {lure['urgency']}")

    if result.delivery_results:
        print(f"\n  Delivery results:")
        for dr in result.delivery_results:
            status = "✓ OK" if dr.success else "✗ FAILED"
            print(f"    • {status} → {dr.recipient} ({dr.subject})")

    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
