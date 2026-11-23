# Nymbric Lure Framework

A real lure generation framework for Nymbric that allows AI agents to ingest personal context from OSINT sources and generate deployable phishing lures delivered via email.

## Overview

This framework provides:

- **OSINT data collection** from LinkedIn, GitHub, Twitter/X, news, and breached PKG files
- **Lure generation** with realistic templates (job offers, invoices, security alerts, etc.)
- **Email delivery** via SMTP with OAuth2 support
- **Artifact packaging** (JSON, YAML, EML, ZIP)

## Architecture

```
src/nymbric/
├── tools/
│   ├── osint/
│   │   ├── __init__.py       # Registry entry point
│   │   ├── scraper.py        # Web scraping utilities
│   │   ├── breacher.py       # Breached PKG loader
│   │   └── aggregator.py     # Evidence merging
│   └── deliverer/
│       ├── __init__.py
│       └── transport/
│           └── email.py      # SMTP delivery with OAuth2
├── lures/
│   └── real/
│       ├── __init__.py
│       ├── templates.py      # Lure templates
│       ├── generator.py      # Lure generation
│       └── renderer.py       # Artifact rendering
└── orchestration/
    └── lure_orchestrator.py  # Main orchestration logic
```

## Quick Start

```bash
# Install dependencies
pip install requests beautifulsoup4 pyyaml

# Run the CLI
python cli.py --target-name "John Doe" --target-email "john@example.com"
```

## CLI Usage

```bash
python cli.py --help
```

### Arguments

| Argument | Description |
|----------|-------------|
| `--target-name` | Target person's name (required) |
| `--target-email` | Target person's email |
| `--target-employer` | Target's employer |
| `--target-location` | Target's location |
| `--link-url` | User-controlled link URL to inject |
| `--sources` | OSINT sources to query (default: linkedin github twitter news) |
| `--template` | Lure template (job_offer, invoice, meeting_invite, security_alert, package_delivery, renewal_notice) |
| `--output-dir` | Output directory for artifacts |
| `--breach-pkg-dir` | Breached PKG directory |
| `--use-oauth2` | Use OAuth2 for email delivery |
| `--dry-run` | Don't actually send emails |

### Examples

```bash
# Basic run
python cli.py --target-name "John Doe" --target-email "john@example.com"

# With custom link URL
python cli.py --target-name "Jane Smith" --target-employer "Acme Corp" --link-url "https://example.com/phish"

# Security alert template
python cli.py --target-name "Bob Wilson" --sources linkedin github --template security_alert

# Dry run (no actual emails sent)
python cli.py --target-name "Alice Brown" --dry-run
```

## Lure Templates

| Template | Description |
|----------|-------------|
| `job_offer` | Fake job offer with onboarding link |
| `invoice` | Fake invoice with payment link |
| `meeting_invite` | Fake meeting invitation |
| `security_alert` | Fake security breach alert |
| `package_delivery` | Fake package delivery notification |
| `renewal_notice` | Fake subscription renewal notice |

## OSINT Sources

- **LinkedIn** - Scrapes profile, email, location, employer
- **GitHub** - Scrapes profile, email, location
- **Twitter/X** - Scrapes profile, email, location
- **News** - Google search for the target name
- **Breached PKG** - Scans local breached PKG files for target mentions

## Email Delivery

The framework supports:

- **SMTP** with TLS
- **OAuth2** authentication (Google, Microsoft, etc.)
- **Plain** authentication (for testing)
- **Batch** delivery to multiple recipients

## Safety

- All attachments are **flag files** saying "You Got Pwned!"
- No real malicious content is generated
- The `--link-url` parameter is **user-controlled** - you decide what URL to inject
- Everything else is generated from OSINT data

## License

MIT License
