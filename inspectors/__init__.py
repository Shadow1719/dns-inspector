"""Inspectors package: real module boundaries for each Inspector BEMO inspector.

`inspectors/dns` is the first boundary, established by migrating a small,
already-tested slice out of `app.py` (see docs/MODULARIZATION.md). Further
DNS Inspector logic remains in `app.py` pending future, separately-scoped
extractions.
"""
