import subprocess

import httpx

from argo.dataset.datadog import (
    SamplePath,
    download_sample,
    list_sample_paths,
    package_name_from_dir,
    parse_sample_path,
    raw_url,
)

SCOPED = "samples/npm/compromised_lib/@ctrl@tinycolor/4.1.1/2025-09-15-@ctrl_tinycolor-v4.1.1.zip"


def test_package_name_from_dir():
    assert package_name_from_dir("@ctrl@tinycolor") == "@ctrl/tinycolor"
    assert package_name_from_dir("02-echo") == "02-echo"


def test_parse_sample_path():
    sp = parse_sample_path(SCOPED)
    assert sp == SamplePath("compromised_lib", "@ctrl/tinycolor", "4.1.1", "2025-09-15", SCOPED)
    assert sp.id == "@ctrl/tinycolor@4.1.1"
    assert parse_sample_path("samples/npm/manifest.json") is None
    assert parse_sample_path("samples/pypi/malicious_intent/x/1.0/2025-01-01-x.zip") is None


def test_raw_url_quotes_at_sign():
    assert "%40ctrl%40tinycolor" in raw_url(SCOPED)


def test_download_is_cached(tmp_path):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=b"zipbytes")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    sp = parse_sample_path(SCOPED)
    assert sp is not None
    p1 = download_sample(sp, tmp_path, client)
    p2 = download_sample(sp, tmp_path, client)
    assert p1 == p2 and p1.read_bytes() == b"zipbytes" and len(calls) == 1


def test_list_sample_paths_from_git(tmp_path):
    repo = tmp_path / "repo"
    f = repo / "samples/npm/malicious_intent/evil/1.0.0/2025-02-01-evil-v1.0.0.zip"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"x")
    (repo / "samples/npm/manifest.json").write_text("{}")
    git = ["git", "-C", str(repo)]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run(
        [*git, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x"], check=True
    )
    paths = list_sample_paths(repo)
    assert [p.id for p in paths] == ["evil@1.0.0"]
