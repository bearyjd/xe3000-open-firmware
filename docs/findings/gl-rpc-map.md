# Bounded RPC and access-control observations

Links into `build/`, `findings/raw/` or `/tmp/` refer to local evidence only; those files are not hosted in this repository. Local `build/openwrt` references describe the inspected checkout and any explicitly identified experiments, not a published upstream source snapshot.

Curated static/captured evidence, 2026-10-31. The six approved paid runs completed with partial extraction. These bounded interpretations received independent semantic review; they do not establish runtime behavior or hardware acceptance. See [coverage and accounting](index.md). No proprietary source excerpts are reproduced.

The fan handler commits a supplied temperature to glfan and invokes service restart; its read handler supplies defaults of 75. The init script maps configuration to daemon arguments and declares respawn. This source linkage does not prove successful invocation, thermal response or the daemon control law. Evidence: [fan:84](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/lib/oui-httpd/rpc/fan#L84), [etc%init.d%gl_fan:20](../../build/review-20261031/harvest/redacted/sys/etc%25init.d%25gl_fan#L20).

The access helper permits a session marked local with a glinet header, permits root ACL groups, then consults group permissions. This is helper-local logic; session construction and upstream callers remain relevant. The no-auth map body has a masked declaration. No remote bypass, universal policy or externally reachable vulnerability is established. Evidence: [rpc.lua:58](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/lib/lua/oui/rpc.lua#L58), [rpc.lua:102](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/lib/lua/oui/rpc.lua#L102).

The ubus proxy source forwards decoded object/method/parameters and initializes a Unix-socket listener. Socket permissions, callers and deployment reachability are unverified; this does not establish unauthenticated network access. Evidence: [gl-ngx-session:579](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/sbin/gl-ngx-session#L579).

Captured blacklist configuration enables black mode with empty visible lists and guest-isolation settings. A separate init script consumes that configuration for list controls and an isolation mask. Actual enforcement, blocked clients and a specific vendor RPC/ACL granting list changes remain unproven. Evidence: [etc%config%gl-black_white_list:1](../../build/review-20261031/harvest/redacted/config/etc%25config%25gl-black_white_list#L1), [gl-black_white_list:42](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/etc/init.d/gl-black_white_list#L42).

This page is a selected map, not an exhaustive list of firmware methods. Chunk-local absence or method-count claims are not promoted to whole-file or whole-firmware conclusions.
