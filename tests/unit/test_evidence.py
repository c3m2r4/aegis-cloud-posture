from aegis.evidence import safe_endpoint_url


def test_safe_endpoint_rendering_does_not_disclose_url_credentials_or_path():
    value = safe_endpoint_url("https://user:password@example.com/private/token-path?token=query-secret#fragment")
    assert value.startswith("https://example.com/[path-sha256-")
    for secret in ("user", "password", "private", "token-path", "query-secret", "fragment"):
        assert secret not in value
