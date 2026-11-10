from nymbric.experiments.security_suite import TESTS, run_security_suite


def test_twelve_security_tests_separate_compliant_and_noncompliant_behavior():
    assert len(TESTS) >= 12
    results = run_security_suite()
    assert len(results) == len(TESTS)
    for result in results:
        assert result["compliant_passed"], result
        assert result["noncompliant_primary_failed"], result
