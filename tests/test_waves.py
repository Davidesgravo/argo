from argo.dataset.waves import matches_any_signature, signature, wave_for_date
from tests.helpers import make_pkg, pkg_json

W1 = make_pkg(
    {"package.json": pkg_json(scripts={"postinstall": "node bundle.js"}), "bundle.js": "x"}
)
W2 = make_pkg(
    {
        "package.json": pkg_json(scripts={"preinstall": "node setup_bun.js"}),
        "setup_bun.js": "x",
        "bun_environment.js": "y",
    }
)
W3_TANSTACK = make_pkg(
    {
        "package.json": pkg_json(
            optionalDependencies={"@tanstack/setup": "github:tanstack/router#79ac"}
        ),
        "router_init.js": "x",
    }
)
W3_ANTV = make_pkg(
    {"package.json": pkg_json(scripts={"preinstall": "bun run index.js"}), "index.js": "x"}
)
BENIGN = make_pkg(
    {"package.json": pkg_json(scripts={"postinstall": "node install.js"}), "install.js": "x"}
)


def test_signatures():
    assert signature("shai_hulud_w1", W1)
    assert signature("shai_hulud_w2", W2)
    assert signature("shai_hulud_w3", W3_TANSTACK)
    assert signature("shai_hulud_w3", W3_ANTV)
    assert not signature("shai_hulud_w1", W2)


def test_benign_install_script_matches_no_wave():
    assert not matches_any_signature(BENIGN)


def test_wave_for_date():
    assert wave_for_date("2025-09-15").subgroup == "shai_hulud_w1"
    assert wave_for_date("2025-11-24").subgroup == "shai_hulud_w2"
    assert wave_for_date("2026-05-19").subgroup == "shai_hulud_w3"
    assert wave_for_date("2025-09-08") is None
