#!/usr/bin/env python3
"""Foundation baseline benchmark harness for the 0.8.6 rebuild (Milestone 1).

NOT executed as part of this hand-off: this sandbox cannot run `python3` at
all (every invocation, including a plain script file, required interactive
approval that was never available in this non-interactive session). This
script is provided ready to run manually so the real numbers can be
collected and compared against the production 0.7.14 baseline this
milestone was asked to report against (~244 MiB RSS after 3d17h uptime, 11
threads, 11 FDs, tracemalloc 0.77 MiB current / 97.8 MiB peak).

Usage:

    mkdir -p /tmp/dns-inspector-bench
    DB_PATH=/tmp/dns-inspector-bench/inspector.db \\
    TRACKERDB_PATH=/tmp/dns-inspector-bench/trackerdb.sqlite \\
    AGH_URL= \\
    python3 scripts/foundation_benchmark.py --duration 60

It imports app.py in-process (rather than spawning a subprocess) so
tracemalloc measures the actual application, and starts the same
background threads main() would: the ingest worker, the enrichment queue
worker, and the device-IP cleanup worker. With AGH_URL unset, ingest()
fails fast every poll cycle (AdGuard is not reachable) instead of hanging,
which measures this foundation's idle overhead -- it is not a substitute
for a real multi-day, real-traffic soak test against a configured AdGuard
instance, which this sandbox has no way to run.
"""
import argparse
import os
import sys
import threading
import time
import tracemalloc
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _rss_mb():
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return round(float(line.split()[1]) / 1024.0, 1)
    except Exception:
        pass
    return None


def _fd_count():
    try:
        return len(os.listdir("/proc/self/fd"))
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--duration", type=float, default=60.0, help="seconds to run before the final sample")
    parser.add_argument("--sample-every", type=float, default=5.0, help="seconds between interim samples")
    args = parser.parse_args()

    # Started before importing app.py so every allocation the import itself
    # performs is traced too, matching what /api/observability would report
    # in the historical (now-excluded) memory-diagnostics build.
    tracemalloc.start(10)

    import app  # noqa: E402

    app.init_db()
    app._prune_stale_device_ips()
    threading.Thread(target=app.worker, daemon=True, name="ingest-worker").start()
    threading.Thread(target=app._enrichment_worker, daemon=True, name="enrichment-queue").start()
    threading.Thread(target=app._device_ip_cleanup_worker, daemon=True, name="device-ip-cleanup").start()

    started = time.time()
    while True:
        remaining = args.duration - (time.time() - started)
        if remaining <= 0:
            break
        time.sleep(min(args.sample_every, max(0.1, remaining)))
        current, peak = tracemalloc.get_traced_memory()
        print(
            f"t+{time.time()-started:6.1f}s  RSS={_rss_mb()} MiB  "
            f"threads={threading.active_count()}  fds={_fd_count()}  "
            f"tracemalloc current={current / 1024 / 1024:.2f} MiB "
            f"peak={peak / 1024 / 1024:.2f} MiB",
            flush=True,
        )

    current, peak = tracemalloc.get_traced_memory()
    print("--- final ---")
    print(f"RSS_MB={_rss_mb()}")
    print(f"THREADS={threading.active_count()}")
    print(f"FDS={_fd_count()}")
    print(f"TRACEMALLOC_CURRENT_MB={round(current / 1024 / 1024, 2)}")
    print(f"TRACEMALLOC_PEAK_MB={round(peak / 1024 / 1024, 2)}")


if __name__ == "__main__":
    main()
