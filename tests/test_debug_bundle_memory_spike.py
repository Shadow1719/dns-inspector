"""Issue #73: `Generate Debug Bundle` caused an additional ~5 GB transient
spike on top of normal runtime.

Root cause: `/debug/bundle` built its `runtime.json` from `_observability_payload()`
(which, since the memory-diagnostics extension, always runs `_memory_diagnostics()`)
*and* its `memory-deep.json` from `_deep_debug_memory_snapshot_safe()` -- and
both independently called `tracemalloc.take_snapshot()` (proportional to
however many allocations are currently traced) and `gc.get_objects()`
(proportional to however many objects are currently live), back to back, in
the same request. `memory-deep.json`'s own `tracemalloc`/`python_object_types`
collectors already report a superset of what `_memory_diagnostics()`'s
lineno-grouped top 25/`large_globals` scan adds, so the duplicate pair of
snapshots was pure waste. These tests pin that each expensive primitive is
now invoked exactly once per `/debug/bundle` request.
"""

import io
import json
import zipfile

import pytest


def test_debug_bundle_takes_exactly_one_tracemalloc_snapshot(app_module, client, monkeypatch):
    if not app_module.tracemalloc.is_tracing():
        pytest.skip("tracemalloc is not tracing in this environment (MEMORY_DIAGNOSTICS_ENABLED=0?)")

    calls = []
    real_take_snapshot = app_module.tracemalloc.take_snapshot

    def counting_take_snapshot(*args, **kwargs):
        calls.append(1)
        return real_take_snapshot(*args, **kwargs)

    monkeypatch.setattr(app_module.tracemalloc, "take_snapshot", counting_take_snapshot)

    response = client.get("/debug/bundle")

    assert response.status_code == 200
    assert len(calls) == 1, (
        f"expected exactly one tracemalloc.take_snapshot() per debug bundle, got {len(calls)} -- "
        "this duplicate full-snapshot cost is the debug-bundle memory spike from Issue #73"
    )


def test_debug_bundle_walks_gc_objects_exactly_once(app_module, client, monkeypatch):
    calls = []
    real_get_objects = app_module.gc.get_objects

    def counting_get_objects(*args, **kwargs):
        calls.append(1)
        return real_get_objects(*args, **kwargs)

    monkeypatch.setattr(app_module.gc, "get_objects", counting_get_objects)

    response = client.get("/debug/bundle")

    assert response.status_code == 200
    assert len(calls) == 1, (
        f"expected exactly one gc.get_objects() walk per debug bundle, got {len(calls)} -- "
        "this duplicate full-heap walk is the debug-bundle memory spike from Issue #73"
    )


def test_debug_bundle_runtime_json_omits_duplicate_memory_diagnostics(app_module, client):
    """`runtime.json` should carry the plain observability payload -- the
    heavier `memory_diagnostics` block (its own tracemalloc/gc scan) belongs
    only in `memory-deep.json`, which already reports richer tracemalloc and
    GC-object-type data."""
    response = client.get("/debug/bundle")
    assert response.status_code == 200

    with zipfile.ZipFile(io.BytesIO(response.data)) as z:
        names = set(z.namelist())
        assert "runtime.json" in names
        assert "memory-deep.json" in names

        runtime = json.loads(z.read("runtime.json"))
        assert "memory_diagnostics" not in runtime

        deep_memory = json.loads(z.read("memory-deep.json"))
        assert "tracemalloc" in deep_memory
        assert "python_object_types" in deep_memory
