from py_vulnerable import build_request


def test_build_request_is_offline_and_sets_auth_header():
    req = build_request("https://example.invalid/api", token="t0k3n")
    assert req.method == "GET"
    assert req.url == "https://example.invalid/api"
    assert req.headers["Authorization"] == "Bearer t0k3n"
