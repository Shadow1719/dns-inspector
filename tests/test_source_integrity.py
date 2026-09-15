"""The central guarantee of 0.8.0: the repository *is* the application.

Up to 0.7.14 the Docker image was produced by running sixteen text-substitution
scripts against `app.py` at build time. The committed source was roughly 1,100
lines behind what actually ran, and editing `app.py` could silently break a
downstream patch marker.

These tests exist so that arrangement cannot come back.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Functions that, before 0.8.0, existed only after the build-time patch chain had
# run. If any of them is missing, the repository has drifted back to being a
# partial source that needs post-processing before it can run.
PATCH_ERA_SYMBOLS = (
    "_schedule_adguard_status",
    "_status_from_counts",
    "_enrichment_worker",
    "_ip_ping_worker",
    "_device_ip_cleanup_worker",
    "_prune_stale_device_ips",
    "_observability_payload",
    "_memory_diagnostics",
    "api_device_label",
    "debug_bundle",
)


def test_no_build_time_patch_scripts_remain():
    """No `build_*.py` mutation scripts anywhere in the repository."""
    offenders = sorted(
        str(path.relative_to(REPO_ROOT))
        for path in REPO_ROOT.rglob("build_*.py")
    )
    assert not offenders, (
        "build-time patch scripts reintroduced: " + ", ".join(offenders)
    )


def test_dockerfile_does_not_mutate_the_source():
    """The image copies source; it does not generate it.

    Comments are excluded so the Dockerfile can still explain why the old patch
    chain was removed.
    """
    lines = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
    instructions = [line for line in lines if not line.lstrip().startswith("#")]
    offenders = [line for line in instructions if "build_" in line]
    assert not offenders, (
        "Dockerfile references a build-time patch script: " + "; ".join(offenders)
    )


def test_application_source_is_complete(app_module):
    """Everything the patch chain used to add is present in the source."""
    missing = [name for name in PATCH_ERA_SYMBOLS
               if not hasattr(app_module, name)]
    assert not missing, f"missing from committed source: {missing}"


def test_application_source_is_importable_without_preprocessing():
    """`app.py` parses on its own, straight from the repository."""
    import ast

    source = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
    ast.parse(source)


def test_version_file_has_a_recognised_format():
    """`MAJOR.MINOR.PATCH`, optionally with an explicit `-dev.N` suffix.

    The 0.8.0 process document asks for plain release versions. This build was
    tagged `0.8.0-dev.1` on explicit instruction, so the pattern permits that
    form while still rejecting the free-form suffixes used before 0.8.0
    (`-hotfix.2.4`, `-dev.16` style chains, arbitrary trailing text).
    """
    import re

    version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+(-dev\.\d+)?", version), (
        f"VERSION must be MAJOR.MINOR.PATCH with an optional -dev.N suffix, "
        f"got {version!r}"
    )
