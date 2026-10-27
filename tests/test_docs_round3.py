from conftest import REPO


def test_prp_residual_risk_mentions_round3_gaps():
    prp = (REPO / "docs" / "prp" / "0001-probes.md").read_text().lower()
    sec5 = prp.split("## 5.")[1].split("## 6.")[0]
    for needle in ("symlink", "hardlink", "4-digit", "high-entropy", "init-script"):
        assert needle in sec5, needle
