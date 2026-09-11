import pytest

from argo.extract.manifest import (
    dep_changes,
    is_non_registry,
    lifecycle_scripts,
    outside_files,
    script_targets,
)


def test_lifecycle_scripts_only_install_time():
    m = {"scripts": {"build": "tsc", "postinstall": "node bundle.js", "prepare": "npm run build"}}
    assert lifecycle_scripts(m) == {"postinstall": "node bundle.js", "prepare": "npm run build"}
    assert lifecycle_scripts({"scripts": "nope"}) == {}
    assert lifecycle_scripts(None) == {}


@pytest.mark.parametrize(
    "spec",
    [
        "github:tanstack/router#79ac49e",
        "git+https://x/y.git",
        "https://x/y.tgz",
        "file:../x",
        "user/repo",
        "user/repo#main",
    ],
)
def test_non_registry_specs(spec):
    assert is_non_registry(spec)


@pytest.mark.parametrize("spec", ["^1.2.3", "1.0.0", "latest", ">=2 <3", "npm:other@1", "*"])
def test_registry_specs(spec):
    assert not is_non_registry(spec)


def test_dep_changes_detects_new_non_registry_optional_dependency():
    old = {"dependencies": {"a": "^1.0.0"}}
    new = {
        "dependencies": {"a": "^1.0.0"},
        "optionalDependencies": {"@tanstack/setup": "github:tanstack/router#79ac"},
    }
    [c] = dep_changes(new, old)
    assert (c.field, c.name, c.old, c.non_registry) == (
        "optionalDependencies",
        "@tanstack/setup",
        None,
        True,
    )


def test_dep_changes_version_bump_is_registry():
    [c] = dep_changes({"dependencies": {"a": "^2.0.0"}}, {"dependencies": {"a": "^1.0.0"}})
    assert c.old == "^1.0.0" and not c.non_registry


def test_outside_files():
    m = {"files": ["dist", "src/"], "main": "index.js"}
    paths = ["dist/a.js", "src/b.ts", "router_init.js", "README.md", "package.json", "index.js"]
    assert outside_files(paths, m) == ["router_init.js"]
    assert outside_files(paths, {}) == []
    assert outside_files(["lib/x.js", "y.js"], {"files": ["lib/**/*.js"]}) == ["y.js"]


def test_script_targets():
    files = ["bundle.js", "scripts/setup.js", "index.js"]
    scripts = {
        "postinstall": "node bundle.js && node ./scripts/setup.js",
        "preinstall": "bun run index.js",
    }
    assert script_targets(scripts, files) == ["bundle.js", "scripts/setup.js", "index.js"]
    assert script_targets({"install": "node-gyp rebuild"}, files) == []
