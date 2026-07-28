"""Small non-normative authoring defaults.

Normative token, plan, evidence, and latency budgets are owned by
``core/conformance.json`` and read through the verified contract bundle.  This
module contains only the bounded discovery default needed before a Core bundle
has been activated.
"""

PREFLIGHT_FILE_ITEMS_MAX = 10_000
