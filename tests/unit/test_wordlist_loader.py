import tempfile
from passguard.wordlist_loader import iter_wordlist, load_wordlist_set


def test_wordlist_streaming_and_normalization():
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write("# comment\nPassword\n  12345678  \n\n")
        path = handle.name
    try:
        words = list(iter_wordlist(path, case_fold=True, strip=True))
        word_set = load_wordlist_set(path, case_fold=True, strip=True)
    finally:
        import os
        os.unlink(path)
    assert words == ["password", "12345678"]
    assert "password" in word_set
