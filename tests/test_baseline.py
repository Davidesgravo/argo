from argo.extract.baseline import WEIGHTS, calibrate, features, score
from argo.extract.dossier import build_dossier
from tests.helpers import make_pkg, pkg_json


def test_features_and_score_for_install_payload():
    new = make_pkg(
        {
            "package.json": pkg_json("x", "1", scripts={"postinstall": "node bundle.js"}),
            "bundle.js": ";".join(f"var _0x{i:04x}=1" for i in range(40))
            + ";process.env.NPM_TOKEN",
        }
    )
    d = build_dossier("x", "x", "1", new, make_pkg({"package.json": pkg_json("x", "0")}), "0")
    f = features(d)
    assert f["lifecycle_changed"] and f["target_obfuscated"] and f["credentials"]
    assert score(d) == sum(WEIGHTS[k] for k, on in f.items() if on)


def test_calibrate_picks_separating_threshold():
    assert calibrate([0.0, 0.5, 3.0, 6.0], [False, False, True, True]) == 3.0


def test_calibrate_prefers_higher_threshold_on_ties():
    # thresholds 4.0 and 1.0 both give F1 = 2/3
    assert calibrate([1.0, 2.0, 3.0, 4.0], [True, False, False, True]) == 4.0
