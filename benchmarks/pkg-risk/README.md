# PKG-Risk

Protocol: [docs/methodology.md](../../docs/methodology.md).

```bash
nymbric run pkg-risk --provider mock --conditions all --trials 4 --personas 24 --seed 42
```

Primary metrics: `private_recall`, `unauthorized_disclosure`.

The checked-in example at `examples/mock_pkg_risk_summary.json` is output from this command family using the mock provider and the `familiarity_biased` fixture. Regenerate it rather than editing the numbers.
