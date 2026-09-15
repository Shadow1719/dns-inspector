from dnsinspector.core import runtime as core
from dnsinspector.db import init_db
from dnsinspector.services.ingest import worker

def start_background_services():
    if core._background_started:
        return
    with core._background_start_lock:
        if core._background_started:
            return
        init_db()
        threading.Thread(target=worker, daemon=True, name='dns-inspector-worker').start()
        core._background_started = True
