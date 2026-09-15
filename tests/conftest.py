"""Shared test setup for DNS Inspector.

`app.py` reads its configuration into module-level constants at import time, so
every environment variable the test suite relies on must be set *before* `app`
is imported anywhere. pytest imports `conftest.py` ahead of the test modules,
which makes this the correct place to do it.

The suite is deliberately hermetic: no AdGuard instance, no TrackerDB download,
no DNS resolution and no outbound HTTP. Anything that would reach the network is
pointed at a closed local port so failures are fast and deterministic.
"""

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# A single temporary directory for the whole session. Created at import time
# because the paths below are baked into `app` as module constants.
_TMP = Path(tempfile.mkdtemp(prefix="dns-inspector-tests-"))

os.environ["DB_PATH"] = str(_TMP / "inspector.db")
os.environ["TRACKERDB_PATH"] = str(_TMP / "trackerdb.sqlite")
os.environ["NEIGHBORS_PATH"] = str(_TMP / "neighbors.txt")

# Empty AdGuard URL keeps ingestion inert; the discard port keeps every other
# outbound integration offline and failing immediately.
os.environ["AGH_URL"] = ""
os.environ["AGH_USER"] = ""
os.environ["AGH_PASS"] = ""
os.environ["TRACKERDB_URL"] = "http://127.0.0.1:9/trackerdb.sql"
os.environ["RDAP_URL"] = "http://127.0.0.1:9/domain/"
os.environ["MACVENDOR_URL"] = "http://127.0.0.1:9"
os.environ["NETIFY_URL"] = "http://127.0.0.1:9/hostnames/"

import pytest  # noqa: E402

import app as dns_inspector  # noqa: E402


@pytest.fixture(scope="session")
def tmp_root():
    """The temporary directory backing this test session."""
    return _TMP


@pytest.fixture(scope="session")
def app_module():
    """The imported DNS Inspector application module."""
    return dns_inspector


@pytest.fixture(scope="session")
def initialised_db(app_module):
    """A database that has been through the real `init_db()` path."""
    app_module.init_db()
    return app_module.DB_PATH


@pytest.fixture()
def client(app_module, initialised_db):
    """A Flask test client backed by the initialised database."""
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as test_client:
        yield test_client
