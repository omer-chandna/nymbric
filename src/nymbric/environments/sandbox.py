"""Execution isolation boundary.

Nymbric runs trusted built-in fixtures and API-backed agents inside this process.
A normal subprocess is not treated as a security boundary. Docker isolation is
not required for the synthetic benchmark and is not assumed to be available.

Untrusted agent code is outside the supported execution mode. External network
access is not used by the synthetic world, the mock provider, or the verifiers.
"""


def isolation_status() -> dict[str, str]:
    return {
        "mode": "trusted_in_process",
        "untrusted_code": "disabled",
        "network_for_simulation": "disabled",
        "subprocess_is_security_boundary": "false",
        "limitation": (
            "If you need to execute untrusted agent programs, supply an external "
            "sandbox. Nymbric will not treat a local subprocess as that sandbox."
        ),
    }
