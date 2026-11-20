import os
import tempfile
import time
import tracemalloc

from passguard.hash_utils import compute_ntlm, verify_unix_hash
from passguard.wordlist_loader import iter_wordlist


def test_ntlm_candidate_hashing_benchmark():
    candidate_count = 100_000
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "bench.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(("candidate-password\n" * candidate_count))

        tracemalloc.start()
        started = time.perf_counter()
        table = {compute_ntlm(word): word for word in iter_wordlist(path)}
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert len(table) == 1
        assert elapsed >= 0
        assert peak >= 0


def test_supported_linux_hash_verification_benchmark():
    from passguard.hash_utils import _PASSLIB_CTX
    if not _PASSLIB_CTX:
        return

    field = _PASSLIB_CTX.hash("12345678", scheme="sha512_crypt")
    started = time.perf_counter()
    matches = sum(
        verify_unix_hash(candidate, field)[0]
        for candidate in ("wrong-one", "wrong-two", "12345678")
    )
    elapsed = time.perf_counter() - started
    assert matches == 1
    assert elapsed >= 0
