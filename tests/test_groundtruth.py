from recon import groundtruth as gt

FILES = {
    "redacted/etc/init.d/modem": "echo 'AT+CFUN=1' > /dev/ttyUSB2\necho 'AT^SYSCONFIG?' > x\ninsmod mhi_wwan_ctrl.ko\n"
                                 "echo 12 > /sys/class/gpio/export\nubus call modem get_info\n",
    "redacted/sys/dts.txt": "gpios = <&tlmm 7 0>;\n",
    "redacted/proc/lsmod.txt": "Module Size Used by\nmhi-wwan-ctrl 20480 1\n",
    "redacted/etc/rpc.json": '{"method":"call","params":["SID","modem","get_status",{}]}',
}


def test_extracts_all_four_lists():
    truth = gt.extract(FILES)
    assert {"AT+CFUN", "AT^SYSCONFIG"} <= truth.at_commands
    assert {12, 7} <= truth.gpios
    assert "mhi_wwan_ctrl" in truth.modules
    assert {"modem.get_info", "modem", "get_info", "modem.get_status"} <= truth.rpc_methods


def test_claim_mentions():
    m = gt.mentions("Sends AT+QCFG and AT!GSTATUS; toggles GPIO 99 via module `foo_mod` and ubus call net reload")
    assert {"AT+QCFG", "AT!GSTATUS"} <= m.at_commands
    assert 99 in m.gpios
    assert "net.reload" in m.rpc_methods


def test_ungrounded_reasons():
    truth = gt.extract(FILES)
    assert gt.ungrounded_reasons("Uses AT+CFUN to power the modem", truth) == []
    reasons = gt.ungrounded_reasons("Uses AT+QPOWD and GPIO 99", truth)
    assert any("AT+QPOWD" in r for r in reasons) and any("99" in r for r in reasons)
    assert gt.ungrounded_reasons("generic prose", truth) == []


def test_insmod_prose_is_not_a_module():
    assert "with" not in gt.mentions("The script runs insmod with extra options").modules
    assert "with" not in gt.extract({"f": "# insmod with care\n"}).modules
    assert "real_mod" in gt.extract({"f": "insmod real_mod\n"}).modules


def test_bare_at_commands():
    truth = gt.extract({"f": "printf 'ATZ\\r' > /dev/ttyUSB2\necho ATE0 > x\nATI\n"})
    assert {"ATZ", "ATE0", "ATI"} <= truth.at_commands
    assert gt.ungrounded_reasons("Resets with ATZ and ATE0", truth) == []
    assert any("ATE1" in r for r in gt.ungrounded_reasons("Uses ATE1", truth))


def test_rpc_names_in_prose_are_checked():
    truth = gt.extract({"f": "ubus call modem get_info\n"})
    assert gt.ungrounded_reasons("Calls `modem.get_info` on boot", truth) == []
    assert any("modem.reboot" in r for r in gt.ungrounded_reasons("Calls `modem.reboot` on boot", truth))
    assert any("do_thing" in r for r in gt.ungrounded_reasons("The RPC method `do_thing` toggles it", truth))
    assert gt.ungrounded_reasons("Edits `network.conf` and `run.sh`", truth) == []


def test_prose_rpc_method_requires_quoted_or_structured_names():
    truth = gt.extract({"f": "ubus call modem get_info\n"})
    for prose in ("An RPC method for toggling the fan", "The ubus method to reboot", "RPC method that returns state"):
        assert gt.ungrounded_reasons(prose, truth) == [], prose
    assert any("do_thing" in r for r in gt.ungrounded_reasons("RPC method do_thing toggles it", truth))
    assert any("v2x" not in r and "svc.go" in r for r in gt.ungrounded_reasons("ubus method svc.go runs", truth))
    assert any("reboot" in r for r in gt.ungrounded_reasons("RPC method `reboot` runs", truth))
    assert any("ping2" in r for r in gt.ungrounded_reasons("RPC method ping2 runs", truth))
