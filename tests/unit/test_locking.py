import pytest

from aegis.config import Settings
from aegis.locking import ScanAlreadyRunning, acquire_scan_lock
from aegis.service import run_discovery


def test_scan_lock_prevents_overlapping_discovery_and_releases(tmp_path):
    settings = Settings(database=tmp_path / "assessments.sqlite")
    first = acquire_scan_lock(settings.database)
    try:
        with pytest.raises(ScanAlreadyRunning):
            run_discovery(settings, adapter=object())
    finally:
        first.release()
    # After release the lock can be acquired again, proving failure was not sticky.
    with acquire_scan_lock(settings.database):
        pass
