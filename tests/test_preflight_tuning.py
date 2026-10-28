"""Pre-flight tuning (PRP 0001 follow-up): benign shapes seen on a real redacted tree must scan clean, while
near-miss lookalikes that carry a real value must still be flagged. Every line here is synthetic; the
secret-looking values in the NEGATIVE cases are assembled at runtime."""
from __future__ import annotations

import shutil

import pytest

from conftest import CFG, GITLEAKS_TOML
from recon import preflight

IMAGE_FILE = GITLEAKS_TOML.parent / "gitleaks.image"

# class name -> (relative path inside harvest/redacted, text). Text is redactor OUTPUT, so it is written as-is.
BENIGN = {
    "path-like-values": ("etc/config/dhcp", "\n".join([
        "config dnsmasq",
        "\toption hook '/usr/libexec/example-helper-bin'",
        "\tlist media_dir '/tmp/mountd/disk2_part9'",
        "\toption Bootstrap2 '/luci-static/bootstrap-dark'",
        "",
    ])),
    "path-in-shell-tests": ("etc/init.d/example", "\n".join([
        "#!/bin/sh /etc/rc.common",
        'HELPER_DIR="/usr/share/zoneinfo-data/base"',
        '[ -f "/sys/class/example-device/state_flag" ] && echo 1',
        'if [ -f "/etc/example-config/feature-flags" ]; then',
        "",
    ])),
    "snake-identifiers": ("etc/config/firewall", "\n".join([
        "config rule 'guest_drop_leaked_dns'",
        "config rule6 'vpn_block_guest_leak_6'",
        "\tlist icmp_type 'destination-unreachable'",
        "\tlist icmp_type 'parameter-problem-extended'",
        "/usr/bin/example.sh 'example_action_trigger' \"${iface}\" 'up'",
        "",
    ])),
    "text-options": ("etc/config/firewall", "\n".join([
        "config rule",
        "\toption name 'Allow-Example-Probe-Reply'",
        "",
    ])),
    "uuids": ("etc/config/fstab", "\n".join([
        "config mount",
        "\toption\tuuid\t'1abc234d-5e6f7a8b-9012cde3-fa45bc6d'",
        "config swap",
        "\toption\tuuid\t'abcd1234-5e6f-7a8b-9c0d-ef1234567890'",
        "minidlna_run --uuid '1b2c3d4e-5f6a-7b8c-9d0e-1f2a3b4c5d6e'",
        "",
    ])),
    "shell-var-path-assignments": ("etc/init.d/vars", "\n".join([
        "SERVICE_PID_FILE=/var/run/example.pid",
        "CONFIGFILE=/etc/example-proxy2/example-proxy.toml",
        "frag_low_thresh=393216",
        "",
    ])),
    "titlecase-module-parameter": ("sys/module/example_mhi/parameters/version",
                                   "Example_Tech_PCIE_MHI_Driver_V1.0.0\n"),
    "benign-flag-options": ("etc/config/mcu", "\n".join([
        "config mcu",
        "    option wifi_password_enabled '1'",
        "    option password_required 'true'",
        "    option enable_passwd 'no'",
        "",
    ])),
    "module-alias-lines": ("cmd/modinfo/example", "filename:\t\t/lib/modules/example.ko\nalias:\t\tnet-pf-16-proto-16-family-wgquark-zjx\n"),
    "cli-long-options": ("etc/init.d/example-dns", "\n".join([
        "start_service() {",
        '\tappend_bool "$cfg" authoritative "--dhcp-authoritative"',
        '\txappend "--rebind-localhost-ok"',
        "",
    ])),
    "shell-variable-references": ("etc/hotplug.d/iface/10-example", "\n".join([
        '\techo "PublicKey = ${public_key}" >> "${cfg_file}"',
        '\tuci set example.section.wan="$ipaddr"',
        '\tuci set example.section.key="${new_key}"',
        "",
    ])),
    "ubus-type-descriptor": ("cmd/ubus-list", "\n".join([
        "'example' @1a2b3c4d",
        '\t"getExamplePortStateInfo":{"switch":"String"}',
        "",
    ])),
}


def _uuid() -> str:
    return "-".join(["".join(["7c9e", "6679"]), "7425", "40de", "944b", "".join(["e07fc1f9", "0ae7"])])


def _blob() -> str:
    return "".join(["q8Xv2L", "mZ9aKd", "4TrYb7", "PwNc3H", "s5Jf6"])  # 29 chars, mixed case + digits


NEGATIVE = {
    "slash-led-blob-is-not-a-path": ("etc/n1.txt", f'build_ref = "/{_blob()}"\n'),
    "digit-heavy-snake-blob": ("etc/n2.txt", f"build_ref = '{_blob().lower()[:12]}_{_blob().lower()[12:]}'\n"),
    "mixed-case-option-name-value": ("etc/n3.txt", f"config rule\n\toption name '{_blob()}'\n"),
    "non-uuid-dashed-blob": ("etc/n4.txt", f"build_ref = '{_blob()[:8]}-{_blob()[8:16]}-{_blob()[16:24]}-{_blob()[24:]}x'\n"),
    "var-assignment-with-blob": ("etc/n5.txt", f"API_BLOB={_blob()}Qz\n"),
    "var-assignment-with-mixed-path": ("etc/n6.txt", f"API_BLOB=/{_blob()}Qz/{_blob()}\n"),
    "password-option-with-value-one": ("etc/n7.txt", "config x\n\toption wifi_password '1'\n"),
    "flag-named-option-with-real-value": ("etc/n8.txt", f"config x\n\toption wifi_password_enabled '{_blob()[:12]}'\n"),
    "var-reference-plus-literal": ("etc/n9.txt", 'echo "PublicKey = ${pk}' + _blob()[:10] + '"\n'),
    "literal-in-uci-set": ("etc/n10.txt", 'uci set example.section.key="' + _blob()[:12] + '"\n'),
    "publickey-line-literal": ("etc/n11.txt", f'echo "PublicKey = {_blob()[:12]}"\n'),
    "cli-option-lookalike-blob": ("etc/n15.txt", f'xappend "--{_blob().lower()}"\n'),
    "alias-line-with-blob": ("etc/n12.txt", f"alias:\t\t{_blob()}\n"),
    "ubus-style-key-with-blob-value": ("etc/n13.txt", f'\t"getExampleState":{{"switch":"{_blob()}"}}\n'),
    "path-lowercase-lead-then-blob": ("etc/n16.txt", f'build_ref = "/a-{_blob()}"\n'),
    "path-url-lead-then-blob": ("etc/n17.txt", f'url = "/api/v1/x-{_blob()}"\n'),
    "path-json-lead-then-blob": ("etc/n18.txt", f'"cloud": "/k-{_blob()}"\n'),
    "path-multi-segment-blob": ("etc/n19.txt", f'build = "/0_{_blob()}/k3-{_blob()}"\n'),
    "path-tmp-prefix-then-blob": ("etc/n20.txt", f'build_ref = "/tmp/a-{_blob()}"\n'),
    "var-assignment-path-lead-then-blob": ("etc/n21.txt", f"API_BLOB=/a-{_blob()}\n"),
    "alias-prefix-then-mixed-blob": ("etc/n22.txt", f"alias:\t\tgh-{_blob()}\n"),
    "ubus-blob-as-outer-key": ("etc/n23.txt", f'\t"{_blob()}":{{}}\n'),
    "ubus-blob-as-inner-key": ("etc/n24.txt", f'\t"x":{{"{_blob()}":"String"}}\n'),
    "ubus-letters-only-blob-key": ("etc/n25.txt", '\t"XkQzMvBtPlRwNhSdQfJzWq":{"a":"String"}\n'),
    "ssid-option-is-not-allowlisted": ("etc/n26.txt", "config wifi-iface\n\toption ssid 'XkQzMvBtPlRw-NhSdQfJzWq'\n"),
    "name-option-mixed-case-words": ("etc/n27.txt", "config rule\n\toption name 'Xq-Kd-Tr-Pw-Nc-Hs-Jf-Lm'\n"),
    "text-option-long-words": ("etc/n28.txt", "config rule\n\tlist text 'Abcdefghijklmnop-Qrstuvwxyzabcdef-Ghijklmnop'\n"),
    "uuid-in-json-key-device-bind": ("etc/n29.txt", f'{{"device_bind": "{_uuid()}"}}\n'),
    "uuid-in-quoted-assignment": ("etc/n30.txt", f'cloud_ref = "{_uuid()}"\n'),
    "single-quoted-literal-in-uci-set": ("etc/n31.txt", "uci set example.section.key='$actualLiteral1'\n"),
    "single-quoted-literal-in-assignment": ("etc/n32.txt", "API_KEY='$actualLiteral1'\n"),
    "module-passphrase-outside-parameters": ("etc/n33.txt", "Velvet_Quick_Harbor_Sphinx\n"),
    "module-passphrase-in-version-file": ("sys/module/example/parameters/version", "Velvet_Quick_Harbor_Sphinx\n"),
    "psk-option-with-real-value": ("etc/n14.txt", f"config x\n\toption wpa_psk '{_blob()[:12]}'\n"),
}


def _scan(root, rel, text):
    red = root / "harvest" / "redacted"
    target = red / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    podman = shutil.which("podman")
    local = CFG["gitleaks_bin"]
    return preflight.run_preflight([red], root, config=GITLEAKS_TOML, podman=None if local else [podman],
                                   image=preflight.read_image(IMAGE_FILE), gitleaks_bin=local,
                                   accept_local_binary=bool(local))


@pytest.mark.requires_gitleaks
@pytest.mark.parametrize("name", sorted(BENIGN))
def test_benign_shape_scans_clean(root, name):
    rel, text = BENIGN[name]
    res = _scan(root, rel, text)
    assert res.hits == (), [(h.line, h.rule) for h in res.hits]
    assert res.stamp is not None


@pytest.mark.requires_gitleaks
@pytest.mark.parametrize("name", sorted(NEGATIVE))
def test_lookalike_with_real_value_is_still_flagged(root, name):
    rel, text = NEGATIVE[name]
    res = _scan(root, rel, text)
    assert res.hits, "lookalike with a secret-shaped value must not be allowlisted"
    assert res.stamp is None
