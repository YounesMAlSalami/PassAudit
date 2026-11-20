from passguard.hash_utils import (
    compute_ntlm,
    md4_hex,
    parse_unix_hash_field,
    verify_unix_hash,
    can_verify_algo,
)


def test_ntlm_known_vectors():
    assert compute_ntlm("password") == "8846F7EAEE8FB117AD06BDD830B7586C"
    assert compute_ntlm("Password") == "A4F49C406510BDCAB6824EE7C30FD852"
    assert compute_ntlm("") == "31D6CFE0D16AE931B73C59D7E0C089C0"
    assert md4_hex(b"") == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_shadow_field_parse_sha512_rounds_salt():
    field = "$6$rounds=656000$NaclSalt$hashvalue"
    parsed = parse_unix_hash_field(field)
    assert parsed["algo_id"] == "6"
    assert parsed["algo_name"] == "SHA-512 (crypt)"
    assert parsed["salt"] == "NaclSalt"
    assert parsed["rounds"] == "656000"


def test_locked_empty_disabled_fields():
    assert parse_unix_hash_field("")["status"] == "empty"
    assert parse_unix_hash_field("!")["status"] == "locked"
    assert parse_unix_hash_field("*")["status"] == "disabled"


def test_sha512_real_verification_when_supported():
    from passguard.hash_utils import _PASSLIB_CTX
    if not _PASSLIB_CTX:
        assert not can_verify_algo("6")
        return
    field = _PASSLIB_CTX.hash("12345678", scheme="sha512_crypt")
    assert can_verify_algo("6")
    assert verify_unix_hash("12345678", field) == (True, "matched")
    assert verify_unix_hash("wrong-password", field) == (False, "no_match")


def test_yescrypt_real_verification_when_backend_available():
    try:
        import yescrypt
    except ImportError:
        assert not can_verify_algo("y")
        return

    field = yescrypt.hash_password("12345678")
    parsed = parse_unix_hash_field(field)
    assert parsed["algo_name"] == "YESCRYPT"
    assert can_verify_algo("y")
    assert verify_unix_hash("12345678", field) == (True, "matched")
    assert verify_unix_hash("wrong-password", field) == (False, "no_match")
