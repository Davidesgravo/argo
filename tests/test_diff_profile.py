from argo.extract.diff import diff_files
from argo.extract.profile import is_binary, profile_file, shannon_entropy
from tests.helpers import make_pkg


def test_diff_statuses_and_order():
    old = make_pkg({"package.json": "{}", "a.js": "1", "gone.js": "x"})
    new = make_pkg({"package.json": '{"v":2}', "a.js": "1", "small.js": "1", "big.js": "1" * 100})
    got = [(c.status, c.path) for c in diff_files(new, old)]
    assert got == [
        ("added", "big.js"),
        ("added", "small.js"),
        ("modified", "package.json"),
        ("removed", "gone.js"),
    ]


def test_diff_without_old_means_all_added():
    assert {c.status for c in diff_files(make_pkg({"a": "1", "b": "2"}), None)} == {"added"}


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") == 0.0
    assert 7.9 < shannon_entropy(bytes(range(256)) * 4) <= 8.0


def test_binary_detection():
    assert is_binary(b"\x7fELF\x00\x01") and not is_binary(b"console.log(1)")


def test_profile_obfuscated_single_line_payload():
    data = ("var " + ",".join(f"_0x{i:04x}=1" for i in range(50)) + ";").encode()
    p = profile_file("bundle.js", data)
    assert p.obfuscated and p.lines == 1 and p.hex_identifiers == 50 and not p.binary


def test_profile_plain_readable_code():
    data = b"function add(a, b) {\n  return a + b;\n}\n" * 20
    p = profile_file("lib.js", data)
    assert not p.obfuscated and not p.minified and p.lines == 61


def test_profile_long_encoded_strings():
    blob = b"A" * 400
    p = profile_file("x.js", b"a='" + blob + b"';b='" + blob + b"';c='" + blob + b"';")
    assert p.long_encoded_strings == 3 and p.obfuscated and p.minified
