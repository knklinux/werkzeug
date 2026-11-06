from __future__ import annotations

import pytest

from werkzeug.http import dump_cookie


def test_host_prefix_valid_combination() -> None:
    rv = dump_cookie("__Host-session", "abc", secure=True)
    assert rv == "__Host-session=abc; Secure; Path=/"


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"secure": False},
        {"secure": True, "domain": "example.com"},
        {"secure": True, "path": "/app"},
        {"secure": True, "path": None},
    ],
)
def test_host_prefix_rejects_invalid_attributes(kwargs: dict) -> None:
    with pytest.raises(ValueError, match="__Host-"):
        dump_cookie("__Host-session", "abc", **kwargs)


def test_secure_prefix_allows_domain() -> None:
    rv = dump_cookie("__Secure-session", "abc", secure=True, domain="example.com")
    assert rv == "__Secure-session=abc; Domain=example.com; Secure; Path=/"


def test_secure_prefix_requires_secure() -> None:
    with pytest.raises(ValueError, match="__Secure-"):
        dump_cookie("__Secure-session", "abc")


def test_partitioned_satisfies_secure_requirement() -> None:
    rv = dump_cookie("__Host-session", "abc", partitioned=True)
    assert "Secure" in rv
    assert "Partitioned" in rv


def test_prefixes_are_case_sensitive() -> None:
    # RFC 6265bis defines the prefixes with a case-sensitive match.
    assert dump_cookie("__host-session", "abc") == "__host-session=abc; Path=/"


def test_delete_cookie_requires_secure_for_host_prefix() -> None:
    from werkzeug.wrappers import Response

    response = Response()

    with pytest.raises(ValueError, match="__Host-"):
        response.delete_cookie("__Host-session")

    response.delete_cookie("__Host-session", secure=True)
    header = response.headers["Set-Cookie"]
    assert header.startswith("__Host-session=;")
    assert "Secure" in header
    assert "Max-Age=0" in header
