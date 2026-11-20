import os
import sys
import pytest


pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Real Linux shadow integration test can only run on Linux",
)


def test_real_linux_shadow_accounts_when_available():
    if not os.path.exists("/etc/shadow") or not os.path.exists("/etc/passwd"):
        pytest.skip("/etc/shadow or /etc/passwd is unavailable")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        pytest.skip("Root permission is required to read /etc/shadow")

    from passguard.linux_auditor import audit_linux_shadow

    wordlist = "/tmp/passguard-assignment4-wordlist.txt"
    try:
        with open(wordlist, "w", encoding="utf-8") as handle:
            handle.write("12345678\n@$7W%P!.mity25*y\n")
        report = audit_linux_shadow(
            shadow_path="/etc/shadow",
            passwd_path="/etc/passwd",
            wordlist_path=wordlist,
            workers=1,
        )
    finally:
        try:
            os.unlink(wordlist)
        except FileNotFoundError:
            pass

    names = {finding.username for finding in report.findings}
    if "younes" not in names or "younesalsalami" not in names:
        pytest.skip("Controlled disposable accounts are not present")

    weak = next(finding for finding in report.findings if finding.username == "younes")
    strong = next(finding for finding in report.findings if finding.username == "younesalsalami")
    assert weak.status == "weak"
    assert strong.status in {"no_match", "not_assessed"}
    assert weak.matched_password_masked is not None
    assert strong.matched_password_masked is None
