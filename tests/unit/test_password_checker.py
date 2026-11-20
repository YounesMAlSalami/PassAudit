from passguard.password_analyzer import analyze_password, classify_interactive_password


def test_common_password_category():
    analysis = analyze_password("12345678", in_wordlist=True)
    assert classify_interactive_password(analysis, True) == "COMMON_PASSWORD"


def test_not_in_wordlist_category_does_not_claim_secure():
    analysis = analyze_password("unique-but-not-in-test-list", in_wordlist=False)
    assert classify_interactive_password(analysis, True) in {
        "NOT_IN_WORDLIST",
        "STRONGER_PASSWORD_RECOMMENDED",
    }


def test_incomplete_analysis_category():
    analysis = analyze_password("anything", in_wordlist=False)
    assert classify_interactive_password(analysis, False) == "ANALYSIS_INCOMPLETE"
