# Offline MCU monitor candidate

This candidate applies two reviewable patches to the public package pinned in
`source.json`. It does not select a firmware package, change the accepted r3
checkout, or establish hardware compatibility. The original package defaults
to XE300; both models are compiled and tested here. No charging control is added.

The separate [candidate firmware build](../../../docs/evidence/firmware-candidate-20261101.json)
selects the patched XE3000 model. Its independent audit verified the actual
compile model, UART default and named MCU image files; UART electrical behavior,
units and charging safety remain hardware gates. The native tests below are
separate from that firmware build.

`0001` adds optional `-d SERIAL_DEVICE` and `-s UBUS_SOCKET`; the upstream device
and socket defaults remain unchanged. `0002` validates an entire frame before
publishing a sample, checks numeric ranges without narrowing, bounds serial
frames at 512 bytes, and retains the last valid sample until it expires.

The accepted wire grammar is the ordered compact syntax shown by the pinned
source: XE3000 has `code`, `capacity`, `temp`, `chg_state`, `charge_cycle` in that
order; XE300 has `{OK},SOC,TEMP,CHARGING,CYCLES`. Extra fields, trailing text,
whitespace, plus signs, fractions, embedded NUL, and partial frames are rejected.
LF and CRLF terminators are supported. Overlong/NUL frames are discarded through
the next newline, allowing subsequent valid frames to recover. Invalid input
neither replaces the sample nor refreshes its age.

SOC is 0–100, charging is 0 or 1, and cycles are 0–65535. Temperature accepts the
signed C `int` range; no unsupported physical unit/range assumption is added.
XE300 retains the upstream division by ten. Double storage preserves XE3000's
integer endpoints. The ubus field names remain `soc`, `charging`, `temperature`,
and `cycles`, with `error: 1` when unavailable. Cycles use a 32-bit ubus integer
to prevent the real CLI from rendering values above 32767 as negative numbers.

The freshness limit of 10 seconds is an explicit candidate policy, **not a
hardware-derived limit**. It uses monotonic time and expires at age >=10 seconds.
The upstream three-second polling interval is unchanged.

## Native verification

Acquire the exact public inputs in `source.json` separately; the native builder
performs no network access. The checkout must contain the five package files,
three dependency Makefiles at their listed paths, and the three archives under
`dl/`. Archive hashes are pinned from those public Makefiles, not trusted from
the download cache. The builder verifies the complete package file set both
before and after building. Source remains external to this patch set.

```sh
python3 scripts/mcu_offline.py --checkout PINNED_CHECKOUT --cmake /usr/bin/cmake
python3 -m pytest -q tests/test_mcu_offline.py
```

`--cmake` defaults to the checkout's host CMake. Required native tools include
GCC/G++, make, git, zstd, tar, pkg-config, Python and pytest. Builds use explicit
`/usr/bin/gcc` and a restricted environment. Output must be a dedicated
`build/mcu-offline-*` directory; an existing directory requires the builder's
ownership marker, with no input overlap or escaping links/hardlinks. Cached
dependency files and links are checked against their recorded hashes.

Real json-c, libubox, libubus, ubusd, and the ubus CLI are built into a private
prefix. No internal headers or parser are replaced. Two **native fixture only**
dependency changes are recorded as `ubus-native-only.patch`: relocate ubusd's
compiled socket-directory default into the output, and accept ACL files owned
by the daemon process's uid/gid. Tests provide a private ACL authorizing only
the current user's `battery` publication and `info` calls. These dependency
changes are never applied to the firmware package. The json-c archive's
same-directory test-script symlinks are materialized as regular files; other
archive links and special files are rejected.

Tests launch the real MCU daemon against a PTY, a private ubusd, and real CLI
JSON output. The seam catches parser, framing, stale-data and model-selection
faults; it does not test UART electrical behavior, device firmware, actual
temperature units, battery safety or router integration. A host allowing PTYs
and local Unix sockets must run the suite without skips. Reconstruction images
without the verified native fixture skip daemon tests with acquisition guidance;
builder refusal checks still run. `MCU_NATIVE_FIXTURE` can select another owned
fixture directory; stale source/patch/dependency/binary metadata fails validation.

Build evidence records input and patch hashes, commands, native tool versions,
dependency license-file hashes and original package preservation. License
metadata needs care: the package Makefile declares GPL-3.0-or-later, while its C
header says GPL-2.0-or-later; this candidate preserves both declarations and does
not resolve that upstream discrepancy. Dependency declarations are json-c MIT,
libubox ISC and ubus LGPL-2.1. Runtime tests do not establish reproducibility,
production readiness, or suitability for flashing. Sanitizers have not been run.
