from recon import chunking


def test_classify():
    c = chunking.classify
    assert c("redacted/etc/init.d/modem") == "init-script"
    assert c("redacted/etc/hotplug.d/iface/10-x") == "hotplug-script"
    assert c("redacted/etc/config/rpcd") == "uci-config"
    assert c("redacted/sys/board.dts") == "dts"
    assert c("redacted/var/dmesg.txt") == "dmesg"
    assert c("redacted/proc/lsmod.txt") == "module-info"
    assert c("unpacked/usr/lib/rpc-handler.lua") == "rpc-handler"
    assert c("unpacked/usr/bin/tool.sh") == "rootfs-script"
    assert c("redacted/capture.har") == "har"
    assert c("redacted/misc") == "other"


def test_numbered_render_and_window():
    ch = chunking.chunk_files([("redacted/etc/init.d/a", "l1\nl2\nl3\nl4\nl5\nl6\n")])
    assert len(ch) == 1
    text = ch[0].render()
    assert "redacted/etc/init.d/a" in text and "    3| l3" in text
    assert "l1" in ch[0].window("redacted/etc/init.d/a", 3) and "l5" in ch[0].window("redacted/etc/init.d/a", 3)
    assert "l6" not in ch[0].window("redacted/etc/init.d/a", 3)
    assert ch[0].window("redacted/nope", 1) is None
    assert ch[0].window("redacted/etc/init.d/a", 99) is None


def test_splits_large_files_keeping_original_line_numbers():
    body = "\n".join(f"line{i}" for i in range(1, 251)) + "\n"
    chunks = chunking.chunk_files([("redacted/var/dmesg.txt", body)], max_lines=100)
    assert len(chunks) == 3
    assert "  101| line101" in chunks[1].render()
    assert chunks[1].window("redacted/var/dmesg.txt", 101) is not None
    assert chunks[1].window("redacted/var/dmesg.txt", 50) is None


def test_groups_small_same_type_and_separates_types():
    files = [("redacted/etc/init.d/a", "a\n"), ("redacted/etc/init.d/b", "b\n"), ("redacted/var/dmesg.txt", "d\n")]
    chunks = chunking.chunk_files(files, max_lines=100)
    assert sorted(c.artifact_type for c in chunks) == ["dmesg", "init-script"]
    init = next(c for c in chunks if c.artifact_type == "init-script")
    assert set(init.files) == {"redacted/etc/init.d/a", "redacted/etc/init.d/b"}


def test_deterministic_ids():
    f = [("redacted/etc/init.d/a", "a\n")]
    assert chunking.chunk_files(f)[0].chunk_id == chunking.chunk_files(f)[0].chunk_id
    assert chunking.chunk_files(f)[0].digest() != chunking.chunk_files([("redacted/etc/init.d/a", "b\n")])[0].digest()
