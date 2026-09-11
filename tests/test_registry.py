import httpx
import pytest

from argo.dataset.registry import Registry, RegistryError, previous_version, versions_in_window

TIME = {
    "created": "2020-01-01T00:00:00Z",
    "modified": "2025-09-16T00:00:00Z",
    "1.0.0": "2024-06-01T00:00:00Z",
    "1.1.0-beta.1": "2025-01-10T00:00:00Z",
    "1.1.0": "2025-02-01T00:00:00Z",
    "1.1.1": "2025-09-15T00:00:00Z",
    "1.1.2": "2025-09-15T01:00:00Z",
}


def test_previous_version_basic_and_prerelease_skipped():
    assert previous_version(TIME, "1.1.0") == "1.0.0"


def test_previous_version_excludes_malicious():
    assert previous_version(TIME, "1.1.2", exclude=["1.1.1"]) == "1.1.0"


def test_previous_version_none():
    assert previous_version(TIME, "1.0.0") is None
    assert previous_version(TIME, "9.9.9") is None


def test_versions_in_window():
    assert versions_in_window(TIME, "2025-01-01", "2025-12-31") == ["1.1.0", "1.1.1", "1.1.2"]


def _client(routes: dict[str, bytes]) -> tuple[httpx.Client, list[str]]:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        calls.append(url)
        if url in routes:
            return httpx.Response(200, content=routes[url])
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_registry_caches_packument_and_tarball(tmp_path):
    doc = b'{"versions": {"1.0.0": {"dist": {"tarball": "https://r/t/a-1.0.0.tgz"}}}}'
    client, calls = _client({"https://r/@s%2Fa": doc, "https://r/t/a-1.0.0.tgz": b"tgz"})
    reg = Registry(tmp_path, client, base_url="https://r")
    assert reg.tarball("@s/a", "1.0.0").read_bytes() == b"tgz"
    reg.tarball("@s/a", "1.0.0")
    reg.packument("@s/a")
    assert len(calls) == 2


def test_registry_missing_version_raises(tmp_path):
    client, _ = _client({"https://r/a": b'{"versions": {}}'})
    with pytest.raises(RegistryError):
        Registry(tmp_path, client, base_url="https://r").tarball("a", "1.0.0")


def test_registry_missing_package_raises(tmp_path):
    client, _ = _client({})
    with pytest.raises(RegistryError):
        Registry(tmp_path, client, base_url="https://r").packument("nope")
