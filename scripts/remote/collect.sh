#!/bin/sh
# Phase 1 harvest collector. Runs ON the router: ssh root@HOST 'sh -s' < collect.sh
#
# STRICTLY READ-ONLY. No file is written, no /tmp, no mount, no module load, no AT traffic, no modem node is
# opened. The only ubus call is `system board`. Every command has stdin from /dev/null so it cannot consume
# this script (sh -s reads the script from stdin). Deliberately no `set -e`: a missing/failing command must not
# stop the run.
#
# Output is one framed stream on stdout:
#   @@BEGIN <kind> <name>  ...content...  (blank line)  @@END <name> <exit>
# Outside frames: @@MISSING <cmd>, @@SKIPPED <path> <reason>, @@COLLECT-VERSION n, @@DONE <frames>.
# A frame without @@END (dropped connection) is treated as PARTIAL by harvest.sh; no @@DONE = incomplete run.

PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
MAXBYTES=1048576
NFRAMES=0

emit_begin() {
  NFRAMES=$((NFRAMES + 1))
  printf '@@BEGIN %s %s\n' "$1" "$2"
}

emit_end() {
  printf '\n@@END %s %s\n' "$1" "$2"
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

# frame_file KIND PATH [hex]: frame one regular file (text via cat, or hex via od). Silent on non-regular files.
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
  ff_r=
  if command -v readlink >/dev/null 2>&1; then
    ff_r=$(readlink -f "$ff_p" 2>/dev/null </dev/null)
  fi
  if [ -n "$ff_r" ] && is_excluded "$ff_r"; then skipped "$ff_p" excluded-target; return 0; fi
  ff_l=$(ls -lnL "$ff_p" 2>/dev/null </dev/null)
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
  if [ "$ff_m" = hex ]; then
    od -An -v -tx1 "$ff_p" </dev/null 2>&1
  else
    cat "$ff_p" </dev/null 2>&1
  fi
  ff_rc=$?
  emit_end "${ff_p#/}" "$ff_rc"
}

# opt_file KIND PATH: like frame_file but silent when the path does not exist (optional attributes).
opt_file() {
  [ -e "$2" ] || return 0
  frame_file "$1" "$2" "$3"
}

# frame_cmd KIND NAME CMD [ARGS...]: frame an external command; @@MISSING if it is not installed.
frame_cmd() {
  fc_k=$1
  fc_n=$2
  shift 2
  if ! command -v "$1" >/dev/null 2>&1; then missing "$1"; return 0; fi
  emit_begin "$fc_k" "$fc_n"
  "$@" </dev/null 2>&1
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
    if [ -e "$mp_d" ] || [ -L "$mp_d" ]; then ls -l "$mp_d" </dev/null 2>&1; fi
  done
  return 0
}

# Owners: /proc/<pid>/fd/<n> symlink targets that point at modem nodes, plus the owning process name (comm).
modem_owners() {
  for mo_f in /proc/[0-9]*/fd/*; do
    mo_t=$(readlink "$mo_f" 2>/dev/null </dev/null)
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

# Fallback only when /sys/firmware/fdt is absent: every /proc/device-tree property as hex (depth <= 6).
dt_fallback() {
  for dt_p in /proc/device-tree/* /proc/device-tree/*/* /proc/device-tree/*/*/* \
              /proc/device-tree/*/*/*/* /proc/device-tree/*/*/*/*/* /proc/device-tree/*/*/*/*/*/*; do
    opt_file hw-dt "$dt_p" hex
  done
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
  if [ -e /sys/firmware/fdt ]; then
    frame_file hw-bin /sys/firmware/fdt hex
  else
    missing /sys/firmware/fdt
    dt_fallback
  fi
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

collect_kernel() {
  frame_cmd kernel cmd/lsmod lsmod
  if command -v modinfo >/dev/null 2>&1; then km_has=1; else km_has=; missing modinfo; fi
  while read -r km_m km_rest; do
    case $km_m in ''|*[!A-Za-z0-9_-]*) continue ;; esac
    if [ -n "$km_has" ]; then frame_cmd kernel "cmd/modinfo/$km_m" modinfo "$km_m"; fi
    for km_a in version srcversion taint; do
      opt_file kernel "/sys/module/$km_m/$km_a"
    done
    for km_a in "/sys/module/$km_m"/parameters/*; do
      opt_file kernel "$km_a"
    done
  done < /proc/modules
  frame_cmd kernel cmd/dmesg dmesg
  frame_cmd kernel cmd/ls-lib-modules ls -lR /lib/modules
}

collect_system() {
  frame_cmd sys cmd/ubus-list ubus -v list
  frame_cmd sys cmd/ubus-call-system-board ubus call system board
  frame_cmd sys cmd/ps ps w
  frame_cmd sys cmd/netstat netstat -lntup
  for cs_f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    opt_file sys "$cs_f"
  done
  frame_cmd sys cmd/ls-init ls -l /etc/init.d /etc/rc.d
  for cs_d in /etc/hotplug.d/*; do
    [ -d "$cs_d" ] || continue
    frame_cmd sys "cmd/ls${cs_d}" ls -l "$cs_d"
    for cs_f in "$cs_d"/*; do
      opt_file sys "$cs_f"
    done
  done
  for cs_f in /etc/init.d/* /etc/crontabs/*; do
    opt_file sys "$cs_f"
  done
  frame_cmd sys cmd/logread logread
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

main() {
  printf '@@COLLECT-VERSION 1\n'
  collect_identity
  collect_hardware
  collect_kernel
  collect_system
  collect_config
  collect_modem
  printf '@@DONE %s\n' "$NFRAMES"
}

# COLLECT_NO_MAIN lets the offline tests source the functions; it is never set on the router.
if [ -z "${COLLECT_NO_MAIN:-}" ]; then main; fi
