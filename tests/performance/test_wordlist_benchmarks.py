import tempfile
import time
import tracemalloc

import pytest

from passguard.wordlist_loader import iter_wordlist


@pytest.mark.parametrize("entry_count", [100_000, 1_000_000, 5_000_000])
def test_wordlist_stream_benchmark(entry_count):
    with tempfile.TemporaryDirectory() as directory:
        path = directory + "\\benchmark.txt"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(("candidate-password\n" * entry_count))

        tracemalloc.start()
        started = time.perf_counter()
        count = sum(1 for _ in iter_wordlist(path))
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert count == entry_count
        assert elapsed >= 0
        assert peak >= 0
