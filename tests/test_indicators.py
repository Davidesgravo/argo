import pytest

from argo.extract.indicators import is_code, scan_package, scan_text
from tests.helpers import make_pkg


@pytest.mark.parametrize(
    "line,category",
    [
        ("exec('curl -fsSL https://bun.sh/install | bash')", "runtime_download"),
        ("await fetch('https://api.github.com/user/repos', {method: 'POST'})", "propagation"),
        ("const t = process.env.NPM_TOKEN", "credentials"),
        ("fs.readFileSync(home + '/.npmrc')", "credentials"),
        ("require('child_process').execSync(cmd)", "exec"),
        ("new Function(atob(x))()", "exec"),
        ("String.fromCharCode(104, 105)", "obfuscation"),
        ("https.request('https://evil-collector.xyz/c')", "network"),
        ("post('http://45.9.148.108:8080/')", "network"),
    ],
)
def test_categories(line, category):
    assert category in {h.category for h in scan_text("x.js", line)}


@pytest.mark.parametrize(
    "line",
    [
        "if (process.env.NODE_ENV === 'production') {}",
        "see https://github.com/org/repo and https://registry.npmjs.org/x",
        "const m = /a(b)/.exec(s)",
    ],
)
def test_common_benign_code_is_quiet(line):
    assert scan_text("x.js", line) == []


def test_line_numbers_and_caps():
    text = "ok\n" + "eval(a)\n" * 10
    hits = [h for h in scan_text("x.js", text) if h.category == "exec"]
    assert len(hits) == 3 and hits[0].line == 2


def test_hex_identifier_aggregate():
    text = ";".join(f"var _0x{i:04x}=1" for i in range(25))
    assert any("25 obfuscator-style" in h.snippet for h in scan_text("x.js", text))


def test_is_code():
    assert is_code("a/b.js") and is_code("x.mjs") and is_code("run.sh")
    assert not is_code("types.d.ts") and not is_code("README.md") and not is_code("a.js.map")


def test_scan_package_skips_non_code_and_missing():
    pkg = make_pkg({"a.js": "eval(x)", "README.md": "eval(x)", "b.bin": b"\x00eval("})
    hits = scan_package(pkg, ["a.js", "README.md", "b.bin", "missing.js"])
    assert {h.path for h in hits} == {"a.js"}
