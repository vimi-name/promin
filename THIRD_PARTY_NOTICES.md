# Third-party notices

The canonical `promin` archive does not vendor third-party source, wheels,
executables, or font files. Dependencies installed by an operator retain their
own licenses and notices.

## Runtime dependencies

| Dependency | Constraint | License | Purpose |
|---|---|---|---|
| `cryptography` | `>=44,<47` | Apache-2.0 OR BSD-3-Clause | Ed25519 decision signature verification |
| `jsonschema` | `>=4.20,<5` | MIT | Draft 2020-12 structural validation |
| `pypdf` | `>=5,<7` | BSD-3-Clause | strict PDF parsing, page counts, and text-extraction diagnostics |

## Build and optional dependencies

| Dependency | Constraint | License | Purpose |
|---|---|---|---|
| `setuptools` | `>=75,<82` | MIT | Python build backend |
| `reportlab` | `>=4.2,<5` | BSD-3-Clause | deterministic PDF generation when document rebuild is requested |
| `pytest` | `>=8,<10` | MIT | executable conformance and physical-scale tests |

Offline verification may consume wheels supplied by the operator. Those wheels
and their transitive dependencies are not part of the standard archive and
retain their own license and notice requirements. Platform wheels may include
or link additional third-party components under their respective terms.

PDF regeneration requires operator-supplied font files with exact SHA-256
bindings. The standard records the selected font identity in build evidence but
does not redistribute or grant rights to those fonts. Existing packaged PDFs
can be parsed and verified without access to source fonts.

Python standard-library modules and SQLite are supplied by the selected Python
runtime and are not redistributed by this archive. Provider adapter dispatch
uses Python runtime facilities and adds no direct package dependency.
