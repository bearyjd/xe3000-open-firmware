#!/bin/sh
# Phase 1 harvest collector. Runs ON the router:
#   ssh root@HOST 'sh -s glinet-harvest-collect' < collect.sh          full harvest
#   ssh root@HOST 'sh -s glinet-harvest-collect probe' < collect.sh    capability probe only
#   ssh root@HOST 'sh -s glinet-harvest-collect COLLECT_LOGS=1' < collect.sh   also snapshot logread (opt-in)
# The first argument is only a tag so the run can be found and stopped:
#   ssh root@HOST "pkill -f '[s]h -s glinet-harvest-collect'"   (bracket form: does not match its own shell)
#
# STRICTLY READ-ONLY. No file is written, no /tmp, no mount, no module load, no AT traffic, no modem node is
# opened. The only ubus call is `system board`. Every command has stdin from /dev/null so it cannot consume
# this script (sh -s reads the script from stdin). Every external read is capped by `timeout 10` when the router
# has `timeout`, and file reads are capped at MAXBYTES, so a blocked /proc or /sys read cannot hang the run for
# more than ~10 s. Deliberately no `set -e`: a missing/failing command must not stop the run.
#
# Output is one framed stream on stdout. The first line announces a per-run nonce; only END/DONE lines carrying
# that nonce are trusted by harvest.sh, so file content cannot forge a frame boundary:
#   @@COLLECT-VERSION 2 <nonce>
#   @@BEGIN <kind> <name>  ...content...  (blank line)  @@END-<nonce> <name> <exit>
#   @@MISSING <cmd> / @@SKIPPED <path> <reason>   (outside frames)
#   @@DONE-<nonce> <frames>
# A frame without @@END (dropped connection) is PARTIAL; no @@DONE = incomplete run. Exit 124 (coreutils) or 143 (BusyBox timeout exec's and reports SIGTERM) = that command was capped by timeout.

PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
MAXBYTES=1048576
MAXMODINFO=200
NFRAMES=0
HEX=
FDT=/sys/firmware/fdt
MODULES_FILE=/proc/modules
SYSMODULE=/sys/module
CRONDIR=/etc/crontabs

if command -v timeout >/dev/null 2>&1; then TMO="timeout 10"; else TMO=; fi
if command -v head >/dev/null 2>&1; then HAVE_HEAD=1; else HAVE_HEAD=; fi

NONCE=$(cat /proc/sys/kernel/random/uuid 2>/dev/null </dev/null)
case $NONCE in
  ''|*[!A-Za-z0-9-]*) NONCE=$(date +%s)$$ ;;
esac

MODE=full
COLLECT_LOGS=
for arg in "$@"; do
  case $arg in
    probe) MODE=probe ;;
    COLLECT_LOGS=1) COLLECT_LOGS=1 ;;
  esac
done

emit_begin() {
  NFRAMES=$((NFRAMES + 1))
  printf '@@BEGIN %s %s\n' "$1" "$2"
}

emit_end() {
  printf '\n@@END-%s %s %s\n' "$NONCE" "$1" "$2"
}

missing() {
  printf '@@MISSING %s\n' "$1"
}

skipped() {
  printf '@@SKIPPED %s %s\n' "$1" "$2"
}

# Hard exclusions at collection (PRP section 5): never read these, whatever asks.
is_excluded() {
  case $1 in
    /etc/shadow*|/etc/gshadow*|/etc/dropbear|/etc/dropbear/*) return 0 ;;
    */private/*|*host_key*|*.pem|*.key) return 0 ;;
    *id_rsa*|*id_dsa*|*id_ecdsa*|*id_ed25519*) return 0 ;;
  esac
  case ${1##*/} in
    *serial*|*SERIAL*|*Serial*) return 0 ;;
  esac
  return 1
}

# canon_safe PATH: fails CLOSED. rc 0 only when readlink -f produced an absolute canonical target that is not
# excluded; rc 1 = target could not be computed (no readlink, failure, timeout, empty or relative output); rc 2 = excluded.
canon_safe() {
  cn_p=$1
  command -v readlink >/dev/null 2>&1 || return 1
  cn_r=$($TMO readlink -f "$cn_p" 2>/dev/null </dev/null)
  cn_rc=$?
  if [ "$cn_rc" -ne 0 ] || [ -z "$cn_r" ]; then return 1; fi
  case $cn_r in
    /*) ;;
    *) return 1 ;;
  esac
  if is_excluded "$cn_r"; then return 2; fi
  return 0
}

# frame_file KIND PATH [hex]: frame one regular file (capped text read, or hex). Silent on non-regular files.
frame_file() {
  ff_k=$1
  ff_p=$2
  ff_m=$3
  case $ff_p in
    *[!A-Za-z0-9._/@:+=,#-]*|*/../*|*/..) skipped - unsafe-name; return 0 ;;
  esac
  if is_excluded "$ff_p"; then skipped "$ff_p" excluded; return 0; fi
  if [ ! -e "$ff_p" ]; then missing "$ff_p"; return 0; fi
  if [ ! -f "$ff_p" ]; then return 0; fi
  canon_safe "$ff_p"
  ff_c=$?
  case $ff_c in
    0) ;;
    2) skipped "$ff_p" excluded-target; return 0 ;;
    *) skipped "$ff_p" canon-failed; return 0 ;;
  esac
  ff_l=$($TMO ls -lnL "$ff_p" 2>/dev/null </dev/null)
  if [ -z "$ff_l" ]; then skipped "$ff_p" stat-failed; return 0; fi
  # shellcheck disable=SC2086  # intentional word splitting; path charset above has no glob characters
  set -- $ff_l
  ff_mode=$1
  ff_sz=$5
  case $ff_mode in
    ?r*) ;;
    *) skipped "$ff_p" no-read-permission; return 0 ;;
  esac
  case $ff_sz in
    ''|*[!0-9]*) ;;
    *) if [ "$ff_sz" -gt "$MAXBYTES" ]; then skipped "$ff_p" "size=$ff_sz"; return 0; fi ;;
  esac
  emit_begin "$ff_k" "${ff_p#/}"
  if [ "$ff_m" = hex ] && [ "$HEX" = od ]; then
    $TMO od -An -v -tx1 "$ff_p" </dev/null 2>&1
  elif [ "$ff_m" = hex ] && [ "$HEX" = hexdump ]; then
    $TMO hexdump -v -e '16/1 "%02x " "\n"' "$ff_p" </dev/null 2>&1
  elif [ -n "$HAVE_HEAD" ]; then
    $TMO head -c "$MAXBYTES" "$ff_p" </dev/null 2>&1
  else
    $TMO cat "$ff_p" </dev/null 2>&1
  fi
  ff_rc=$?
  emit_end "${ff_p#/}" "$ff_rc"
}

# opt_file KIND PATH: like frame_file but silent when the path does not exist (optional attributes).
opt_file() {
  [ -e "$2" ] || return 0
  frame_file "$1" "$2" "$3"
}

# frame_cmd KIND NAME CMD [ARGS...]: frame an external command (capped by $TMO); @@MISSING if not installed.
frame_cmd() {
  fc_k=$1
  fc_n=$2
  shift 2
  if ! command -v "$1" >/dev/null 2>&1; then missing "$1"; return 0; fi
  emit_begin "$fc_k" "$fc_n"
  $TMO "$@" </dev/null 2>&1
  fc_rc=$?
  emit_end "$fc_n" "$fc_rc"
}

# frame_fn KIND NAME FUNCTION: frame one of this script's own shell functions.
frame_fn() {
  emit_begin "$1" "$2"
  "$3"
  fn_rc=$?
  emit_end "$2" "$fn_rc"
}

# Modem: device nodes are only stat-ed via ls -l; nothing is ever read from them.
modem_ports() {
  for mp_d in /dev/ttyUSB* /dev/ttyACM* /dev/cdc-wdm* /dev/wwan* /dev/mhi*; do
    if [ -e "$mp_d" ] || [ -L "$mp_d" ]; then $TMO ls -l "$mp_d" </dev/null 2>&1; fi
  done
  return 0
}

# Owners: /proc/<pid>/fd/<n> symlink targets that point at modem nodes, plus the owning process name (comm).
modem_owners() {
  for mo_f in /proc/[0-9]*/fd/*; do
    mo_t=$($TMO readlink "$mo_f" 2>/dev/null </dev/null)
    case $mo_t in
      /dev/ttyUSB*|/dev/ttyACM*|/dev/cdc-wdm*|/dev/wwan*|/dev/mhi*)
        mo_p=${mo_f#/proc/}
        mo_p=${mo_p%%/*}
        mo_c=
        { read -r mo_c < "/proc/$mo_p/comm"; } 2>/dev/null
        printf 'pid=%s comm=%s fd=%s target=%s\n' "$mo_p" "$mo_c" "${mo_f##*/}" "$mo_t"
        ;;
    esac
  done
  return 0
}

# pid + process name only (/proc/<pid>/comm). Command lines (/proc/<pid>/cmdline, ps w) are never collected:
# they carry passwords (pppd, curl -u, mosquitto_pub -P).
proc_comm_table() {
  for pt_d in /proc/[0-9]*; do
    pt_p=${pt_d#/proc/}
    pt_c=
    { read -r pt_c < "/proc/$pt_p/comm"; } 2>/dev/null
    printf '%s %s\n' "$pt_p" "$pt_c"
  done
  return 0
}

# Crontab lines, but only after a conservative filter: any line containing pass, pwd, secret, token, key, auth,
# user, '-u ', '-p ' (either case, with or without a following space), '://', or an assignment whose name looks
# like PW/PSK/API is dropped and only counted.
crontab_filtered() {
  for ct_f in "$CRONDIR"/*; do
    [ -f "$ct_f" ] || continue
    if [ -L "$ct_f" ]; then printf '# skipped %s (symlink)\n' "${ct_f##*/}"; continue; fi
    is_excluded "$ct_f" && continue
    if ! canon_safe "$ct_f"; then printf '# skipped %s (canonical target unknown or excluded)\n' "${ct_f##*/}"; continue; fi
    printf '# file %s\n' "${ct_f##*/}"
    ct_drop=0
    while IFS= read -r ct_l || [ -n "$ct_l" ]; do
      case $ct_l in
        *:*:*:*:*:*:*:*:*|*:\$[0-9a-z]*\$*)
          ct_drop=$((ct_drop + 1)) ;;
        *[Pp][Aa][Ss][Ss]*|*[Pp][Ww][Dd]*|*[Ss][Ee][Cc][Rr][Ee][Tt]*|*[Tt][Oo][Kk][Ee][Nn]*|*[Kk][Ee][Yy]*|*[Aa][Uu][Tt][Hh]*|*[Uu][Ss][Ee][Rr]*|*"-u "*|*"-p "*|*"-U "*|*"-P "*|*-[pPuU][!\ ]*|*://*|*[Pp][Ww]*=*|*[Pp][Ss][Kk]*=*|*[Aa][Pp][Ii]*=*)
          ct_drop=$((ct_drop + 1)) ;;
        *) printf '%s\n' "$ct_l" ;;
      esac
    done < "$ct_f"
    printf '# dropped %s line(s)\n' "$ct_drop"
  done
  return 0
}

# Pick a hex dumper: od, else hexdump; HEX stays empty when neither works.
detect_hex() {
  HEX=
  if command -v od >/dev/null 2>&1 && $TMO od -An -tx1 /dev/null >/dev/null 2>&1; then
    HEX="od"
  elif command -v hexdump >/dev/null 2>&1 && $TMO hexdump -v -e '16/1 "%02x " "\n"' /dev/null >/dev/null 2>&1; then
    HEX="hexdump"
  fi
}

# Fallback when the live DTB cannot be dumped: every /proc/device-tree property (hex if possible), depth <= 6.
dt_fallback() {
  for dt_p in /proc/device-tree/* /proc/device-tree/*/* /proc/device-tree/*/*/* \
              /proc/device-tree/*/*/*/* /proc/device-tree/*/*/*/*/* /proc/device-tree/*/*/*/*/*/*; do
    opt_file hw-dt "$dt_p" hex
  done
}

collect_fdt() {
  detect_hex
  if [ -e "$FDT" ] && [ -n "$HEX" ]; then
    frame_file hw-bin "$FDT" hex
  else
    missing "$FDT"
    dt_fallback
  fi
}

collect_identity() {
  opt_file ident /etc/openwrt_release
  opt_file ident /etc/glversion
  frame_cmd ident cmd/uname uname -a
  for ci_f in /proc/cpuinfo /proc/meminfo /proc/cmdline /proc/mtd /proc/partitions; do
    frame_file ident "$ci_f"
  done
}

collect_hardware() {
  collect_fdt
  frame_cmd hw cmd/ls-pci ls -l /sys/bus/pci/devices
  for hp_d in /sys/bus/pci/devices/*; do
    [ -e "$hp_d" ] || continue
    for hp_a in vendor device subsystem_vendor subsystem_device class; do
      opt_file hw "$hp_d/$hp_a"
    done
    if [ -L "$hp_d/driver" ]; then frame_cmd hw "${hp_d#/}/driver.link" readlink "$hp_d/driver"; fi
  done
  frame_cmd hw cmd/ls-usb ls -l /sys/bus/usb/devices
  for hu_d in /sys/bus/usb/devices/*; do
    [ -e "$hu_d" ] || continue
    for hu_a in idVendor idProduct manufacturer product; do
      opt_file hw "$hu_d/$hu_a"
    done
  done
  frame_cmd hw cmd/ls-leds ls -l /sys/class/leds
  for hl_d in /sys/class/leds/*; do
    [ -e "$hl_d" ] || continue
    for hl_a in brightness max_brightness trigger; do
      opt_file hw "$hl_d/$hl_a"
    done
  done
  frame_cmd hw cmd/ls-gpio ls -l /sys/class/gpio
  collect_hw_risky
}

# hwmon, thermal, power_supply and debugfs gpio reads can block in the kernel. Without a `timeout` applet there is no
# per-read cap, so they are skipped entirely rather than risk hanging the run.
collect_hw_risky() {
  if [ -z "$TMO" ]; then
    skipped /sys/class/hwmon no-timeout
    skipped /sys/class/thermal no-timeout
    skipped /sys/class/power_supply no-timeout
    skipped /sys/kernel/debug/gpio no-timeout
    return 0
  fi
  if [ -f /sys/kernel/debug/gpio ]; then
    frame_file hw /sys/kernel/debug/gpio
  else
    skipped /sys/kernel/debug/gpio not-mounted-or-absent
  fi
  for hh_d in /sys/class/hwmon/*; do
    [ -e "$hh_d" ] || continue
    for hh_a in "$hh_d/name" "$hh_d"/temp*_input "$hh_d"/fan*_input "$hh_d"/pwm*; do
      opt_file hw "$hh_a"
    done
  done
  for ht_d in /sys/class/thermal/*; do
    [ -e "$ht_d" ] || continue
    for ht_a in type temp policy; do
      opt_file hw "$ht_d/$ht_a"
    done
  done
  for hs_d in /sys/class/power_supply/*; do
    [ -e "$hs_d" ] || continue
    for hs_a in "$hs_d"/*; do
      # uevent re-exposes POWER_SUPPLY_SERIAL_NUMBER, so it is not read.
      case $hs_a in */uevent) continue ;; esac
      opt_file hw "$hs_a"
    done
  done
}

# Per-module info: sysfs attributes always; modinfo only when sysfs lacks version/srcversion and the module count
# is sane (a router with hundreds of modules would otherwise fork hundreds of times).
collect_modinfo() {
  km_n=0
  while read -r km_m _; do
    km_n=$((km_n + 1))
  done < "$MODULES_FILE"
  km_has=
  if command -v modinfo >/dev/null 2>&1; then km_has=1; else missing modinfo; fi
  if [ -n "$km_has" ] && [ "$km_n" -gt "$MAXMODINFO" ]; then
    skipped modinfo "module-count=$km_n"
    km_has=
  fi
  while read -r km_m _; do
    case $km_m in ''|*[!A-Za-z0-9_-]*) continue ;; esac
    if [ -n "$km_has" ] && [ ! -e "$SYSMODULE/$km_m/version" ] && [ ! -e "$SYSMODULE/$km_m/srcversion" ]; then
      frame_cmd kernel "cmd/modinfo/$km_m" modinfo "$km_m"
    fi
    for km_a in version srcversion taint; do
      opt_file kernel "$SYSMODULE/$km_m/$km_a"
    done
    for km_a in "$SYSMODULE/$km_m"/parameters/*; do
      opt_file kernel "$km_a"
    done
  done < "$MODULES_FILE"
}

collect_kernel() {
  frame_cmd kernel cmd/lsmod lsmod
  collect_modinfo
  frame_cmd kernel cmd/dmesg dmesg
  frame_cmd kernel cmd/ls-lib-modules ls -lR /lib/modules
}

collect_system() {
  frame_cmd sys cmd/ubus-list ubus -v list
  frame_cmd sys cmd/ubus-call-system-board ubus call system board
  frame_fn sys cmd/proc-comm proc_comm_table
  frame_cmd sys cmd/netstat netstat -lntup
  for cs_f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    opt_file sys "$cs_f"
  done
  frame_cmd sys cmd/ls-init ls -l /etc/init.d /etc/rc.d
  frame_cmd sys cmd/ls-crontabs ls -l /etc/crontabs
  frame_fn sys cmd/crontabs-filtered crontab_filtered
  for cs_d in /etc/hotplug.d/*; do
    [ -d "$cs_d" ] || continue
    frame_cmd sys "cmd/ls${cs_d}" ls -l "$cs_d"
    for cs_f in "$cs_d"/*; do
      opt_file sys "$cs_f"
    done
  done
  for cs_f in /etc/init.d/*; do
    opt_file sys "$cs_f"
  done
  if [ -n "$COLLECT_LOGS" ]; then
    frame_cmd sys cmd/logread logread
  else
    skipped logread logs-not-requested
  fi
}

collect_config() {
  frame_cmd config cmd/ls-config ls -l /etc/config
  for cc_f in /etc/config/*; do
    opt_file config "$cc_f"
  done
}

collect_modem() {
  frame_fn modem cmd/modem-ports modem_ports
  frame_fn modem cmd/modem-owners modem_owners
}

# Probe mode: learn which tools the router's busybox has before the full run. Nothing else is run.
probe_busybox() {
  if command -v busybox >/dev/null 2>&1; then
    busybox --list </dev/null 2>&1 | grep -E '^(od|hexdump|timeout|head|readlink|ls|netstat|logread|lsmod|modinfo|dmesg)$'
  else
    missing busybox
  fi
  return 0
}

probe_commands() {
  for pc_c in od hexdump timeout head readlink ls netstat logread lsmod modinfo dmesg ubus date cat busybox grep pkill pgrep; do
    if command -v "$pc_c" >/dev/null 2>&1; then printf 'present %s\n' "$pc_c"; else printf 'absent %s\n' "$pc_c"; fi
  done
  return 0
}

probe() {
  printf '@@COLLECT-VERSION 2 %s\n' "$NONCE"
  frame_cmd probe cmd/uname uname -a
  frame_fn probe cmd/busybox-list probe_busybox
  frame_fn probe cmd/command-v probe_commands
  printf '@@DONE-%s %s\n' "$NONCE" "$NFRAMES"
}

main() {
  printf '@@COLLECT-VERSION 2 %s\n' "$NONCE"
  collect_identity
  collect_hardware
  collect_kernel
  collect_system
  collect_config
  collect_modem
  printf '@@DONE-%s %s\n' "$NONCE" "$NFRAMES"
}

# COLLECT_NO_MAIN lets the offline tests source the functions; it is never set on the router.
if [ -z "${COLLECT_NO_MAIN:-}" ]; then
  if [ "$MODE" = probe ]; then probe; else main; fi
fi
