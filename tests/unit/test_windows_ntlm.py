from passguard.windows_auditor import parse_hash_file


def test_pwdump_parser():
    import tempfile
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write(
            "weakuser:1001:"
            "AAD3B435B51404EEAAD3B435B51404EE:"
            "8846F7EAEE8FB117AD06BDD830B7586C:::\n"
        )
        path = handle.name
    try:
        entries = parse_hash_file(path)
    finally:
        import os
        os.unlink(path)
    assert entries[0]["username"] == "weakuser"
    assert entries[0]["nt"] == "8846F7EAEE8FB117AD06BDD830B7586C"


def test_empty_ntlm_is_recognized():
    import tempfile
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write("31D6CFE0D16AE931B73C59D7E0C089C0\n")
        path = handle.name
    try:
        entries = parse_hash_file(path)
    finally:
        import os
        os.unlink(path)
    assert entries[0]["format"] == "bare-nt"
    assert entries[0]["nt"] == "31D6CFE0D16AE931B73C59D7E0C089C0"
