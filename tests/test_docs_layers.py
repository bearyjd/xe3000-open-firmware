from conftest import REPO


def test_prp_describes_layers_and_residual_risk():
    prp = (REPO / "docs" / "prp" / "0001-probes.md").read_text()
    for needle in ("default-deny", "recon-allowlist.txt", "canary", "--allow-extra", "--no-canary",
                   "defence in depth", "residual risk"):
        assert needle.lower() in prp.lower(), needle
    sec5 = prp.split("## 5.")[1].split("## 6.")[0]
    assert "allowlist" in sec5.lower() and "canar" in sec5.lower()
    sec10 = prp.split("## 10.")[1]
    assert "regex" in sec10.lower() and "cannot be complete" in sec10.lower()


def test_readme_documents_canary_init():
    readme = (REPO / "README.md").read_text()
    assert "canary-init" in readme and "xe3000-open-firmware/canaries" in readme and "0600" in readme


def test_justfile_has_canary_init_and_passes_canary_to_containers():
    text = (REPO / "justfile").read_text()
    assert "canary-init:" in text and "canary.py" in text
    body = (REPO / "scripts" / "analyze-container.sh").read_text()
    assert "RECON_CANARY_FILE" in body and ":ro" in body.split("RECON_CANARY_FILE", 1)[1][:400]


def test_allowlist_file_is_committed_in_the_analyze_mount():
    assert (REPO / "containers" / "recon-allowlist.txt").is_file()
